#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <json-c/json.h>

// Includes for hostname and IP (local machine)
#include <limits.h>
#include <ifaddrs.h>
// #include <arpa/inet.h> // Included by netdb.h or sys/socket.h often

// Includes for TCP client
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>      // For gethostbyname, getaddrinfo

#include "readline_tracker.skel.h"

#define OUTPUT_LOG_FILE_DEFAULT "/tmp/Output.log"
#define TASK_COMM_LEN 16
#define OUTPUT_STR_LEN 480
#define TCP_REMOTE_PORT 8080 // Hardcoded as requested

struct data_t {
    uint32_t pid;
    char comm[TASK_COMM_LEN];
    char str[OUTPUT_STR_LEN];
};

static volatile bool exiting = false;

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif
static char current_hostname[HOST_NAME_MAX + 1];
static char current_ip_address[NI_MAXHOST];

// TCP Client Globals
static bool g_send_to_tcp_server = false;
static char g_tcp_remote_host[256];
static int g_tcp_socket = -1;
// static struct sockaddr_in g_tcp_serv_addr; // Not strictly needed if reconnecting with getaddrinfo

static bool g_write_to_file = true;
static char g_output_log_file[PATH_MAX];


static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -t, --tcp-server <host>   Send output via TCP to <host> on port %d\n", TCP_REMOTE_PORT);
    printf("  -n, --no-file             Do not write output to the local JSON file\n");
    printf("  -o, --output-file <FILE>  Specify a different local output file (default: %s)\n", OUTPUT_LOG_FILE_DEFAULT);
}

static void sig_handler(int sig) {
    exiting = true;
}

static int connect_to_tcp_server() {
    if (g_tcp_socket != -1) {
        close(g_tcp_socket);
        g_tcp_socket = -1;
    }

    struct addrinfo hints, *servinfo, *p;
    int rv;
    char port_str[12];
    snprintf(port_str, sizeof(port_str), "%d", TCP_REMOTE_PORT);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(g_tcp_remote_host, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "TCP Connect: getaddrinfo for %s:%d failed: %s\n", g_tcp_remote_host, TCP_REMOTE_PORT, gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((g_tcp_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("TCP Connect: socket error");
            continue;
        }
        if (connect(g_tcp_socket, p->ai_addr, p->ai_addrlen) == -1) {
            // perror("TCP Connect: connect error"); // Can be very noisy if server is down
            close(g_tcp_socket);
            g_tcp_socket = -1;
            continue;
        }
        break; // Successfully connected
    }

    freeaddrinfo(servinfo);

    if (p == NULL || g_tcp_socket == -1) {
        fprintf(stderr, "TCP Connect: Failed to connect to %s:%d\n", g_tcp_remote_host, TCP_REMOTE_PORT);
        return -1;
    }

    printf("Successfully connected to TCP server %s:%d\n", g_tcp_remote_host, TCP_REMOTE_PORT);
    return 0;
}

static void send_over_tcp(const char *json_data) {
    if (!g_send_to_tcp_server) return;

    if (g_tcp_socket == -1) {
        if (connect_to_tcp_server() != 0) {
            fprintf(stderr, "TCP Send: Not connected, and failed to reconnect. Dropping data.\n");
            return; // Failed to connect
        }
    }

    // Prepare data with newline
    size_t json_len = strlen(json_data);
    // Max typical JSON string + newline + null terminator. Adjust if events are huge.
    char send_buffer[OUTPUT_STR_LEN + TASK_COMM_LEN + 512]; 
    if (json_len + 1 >= sizeof(send_buffer)) {
        fprintf(stderr, "TCP Send: JSON data too large for send buffer. Dropping.\n");
        return;
    }
    memcpy(send_buffer, json_data, json_len);
    send_buffer[json_len] = '\n';
    send_buffer[json_len + 1] = '\0';
    size_t total_len = json_len + 1;

    ssize_t bytes_sent = send(g_tcp_socket, send_buffer, total_len, 0);
    if (bytes_sent == -1) {
        perror("TCP Send: send error");
        close(g_tcp_socket);
        g_tcp_socket = -1; // Mark as disconnected
    } else if ((size_t)bytes_sent < total_len) {
        fprintf(stderr, "TCP Send: Incomplete send. Sent %zd of %zu bytes.\n", bytes_sent, total_len);
        // Rudimentary handling: assume connection is bad
        close(g_tcp_socket);
        g_tcp_socket = -1;
    }
}


static void get_best_ip_address(char *buffer, size_t buffer_len) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host_buf[NI_MAXHOST];
    strncpy(buffer, "N/A", buffer_len);
    if (getifaddrs(&ifaddr) == -1) { perror("getifaddrs"); return; }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strncmp(ifa->ifa_name, "docker", 6) == 0 || strncmp(ifa->ifa_name, "veth", 4) == 0) continue;
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host_buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) { fprintf(stderr, "getnameinfo() failed for %s: %s\n", ifa->ifa_name, gai_strerror(s)); continue; }
            strncpy(buffer, host_buf, buffer_len);
            buffer[buffer_len - 1] = '\0';
            break;
        }
    }
    freeifaddrs(ifaddr);
}

static void handle_event(void *cb_ctx, int cpu, void *data, __u32 data_sz) {
    const struct data_t *event = data;
    char time_buf[64];
    time_t now;
    struct tm *tm_info;

    if (data_sz < sizeof(struct data_t)) {
        fprintf(stderr, "Error: short event data received, expected %zu, got %u\n", sizeof(struct data_t), data_sz);
        return;
    }

    time(&now);
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%-m/%-d/%Y-%H:%M:%S", tm_info);

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "time", json_object_new_string(time_buf));
    json_object_object_add(jobj, "hostname", json_object_new_string(current_hostname));
    json_object_object_add(jobj, "ip_address", json_object_new_string(current_ip_address));
    json_object_object_add(jobj, "pid", json_object_new_int(event->pid));
    json_object_object_add(jobj, "process", json_object_new_string(event->comm));
    json_object_object_add(jobj, "output", json_object_new_string(event->str));

    if (g_send_to_tcp_server) {
        const char *json_event_string = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
        if (json_event_string) {
            send_over_tcp(json_event_string);
        } else {
            fprintf(stderr, "Failed to convert event to JSON string for TCP. PID: %u, COMM: %s\n", event->pid, event->comm);
        }
    }

    if (g_write_to_file) {
        json_object *jarray = json_object_from_file(g_output_log_file);
        if (!jarray || !json_object_is_type(jarray, json_type_array)) {
            if (jarray) json_object_put(jarray);
            jarray = json_object_new_array();
        }
        json_object_array_add(jarray, json_object_get(jobj));
        if (json_object_to_file_ext(g_output_log_file, jarray, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE) < 0) {
            fprintf(stderr, "Error writing to JSON file %s\n", g_output_log_file);
        }
        json_object_put(jarray);
    }
    json_object_put(jobj);
}

static int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (level <= LIBBPF_WARN) { return vfprintf(stderr, format, args); }
    return 0;
}

int main(int argc, char **argv) {
    struct readline_tracker_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    int opt;

    strncpy(g_output_log_file, OUTPUT_LOG_FILE_DEFAULT, sizeof(g_output_log_file) -1); // Set default

    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"tcp-server",   required_argument, 0, 't'},
        {"no-file",      no_argument,       0, 'n'},
        {"output-file",  required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "ht:no:", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                g_send_to_tcp_server = true;
                strncpy(g_tcp_remote_host, optarg, sizeof(g_tcp_remote_host) - 1);
                g_tcp_remote_host[sizeof(g_tcp_remote_host) - 1] = '\0';
                break;
            case 'n':
                g_write_to_file = false;
                break;
            case 'o':
                strncpy(g_output_log_file, optarg, sizeof(g_output_log_file) - 1);
                g_output_log_file[sizeof(g_output_log_file) - 1] = '\0';
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!g_send_to_tcp_server && !g_write_to_file) {
        fprintf(stderr, "Error: No output method selected. Use --tcp-server or ensure file writing is enabled (default).\n");
        print_usage(argv[0]);
        return 1;
    }

    if (gethostname(current_hostname, sizeof(current_hostname)) != 0) { perror("gethostname"); strncpy(current_hostname, "N/A", sizeof(current_hostname)); }
    current_hostname[sizeof(current_hostname) - 1] = '\0';
    get_best_ip_address(current_ip_address, sizeof(current_ip_address));

    printf("Starting readline tracker...\nHostname: %s, IP: %s\n", current_hostname, current_ip_address);
    if (g_write_to_file) printf("Logging to file: %s\n", g_output_log_file);
    if (g_send_to_tcp_server) {
        printf("Attempting to send data to TCP server: %s:%d\n", g_tcp_remote_host, TCP_REMOTE_PORT);
        // Initial connection attempt. send_over_tcp will also attempt if g_tcp_socket is -1
        connect_to_tcp_server(); 
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) { perror("setrlimit(RLIMIT_MEMLOCK)"); return 1; }

    if (g_write_to_file) {
        FILE *f_check = fopen(g_output_log_file, "r");
        bool initialize_json = true;
        if (f_check) { fseek(f_check, 0, SEEK_END); if (ftell(f_check) > 2) initialize_json = false; fclose(f_check); }
        if (initialize_json) {
            char *last_slash = strrchr(g_output_log_file, '/');
            if (last_slash) {
                char dir_path[PATH_MAX]; size_t dir_path_len = last_slash - g_output_log_file;
                if (dir_path_len < sizeof(dir_path)) {
                    strncpy(dir_path, g_output_log_file, dir_path_len); dir_path[dir_path_len] = '\0';
                    char command[sizeof(dir_path) + 10]; snprintf(command, sizeof(command), "mkdir -p %s", dir_path);
                    if(system(command) != 0) fprintf(stderr, "Warning: failed to execute '%s'\n", command);
                } else fprintf(stderr, "Warning: directory path for log file is too long.\n");
            }
            FILE *f_write = fopen(g_output_log_file, "w");
            if (!f_write) { perror("Failed to open output log file for writing"); return 1; }
            fprintf(f_write, "[]\n"); fclose(f_write);
        }
    }

    libbpf_set_print(print_libbpf_log);
    skel = readline_tracker_bpf__open();
    if (!skel) { fprintf(stderr, "Failed to open BPF skeleton\n"); goto cleanup; }
    err = readline_tracker_bpf__load(skel);
    if (err) { fprintf(stderr, "Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err)); goto cleanup; }
    err = readline_tracker_bpf__attach(skel);
    if (err) { fprintf(stderr, "Failed to attach BPF skeleton: %d (%s)\n", err, strerror(-err)); goto cleanup; }

    printf("eBPF program attached. Waiting for events...\n");
    if (g_write_to_file) printf("File output: %s\n", g_output_log_file);
    if (g_send_to_tcp_server) printf("TCP output: %s:%d\n", g_tcp_remote_host, TCP_REMOTE_PORT);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) { err = -errno; fprintf(stderr, "Failed to create perf buffer: %d (%s)\n", err, strerror(-err)); goto cleanup; }

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "Error polling perf buffer: %d (%s)\n", err, strerror(-err)); break; }
        err = 0;
    }

cleanup:
    if (pb) perf_buffer__free(pb);
    if (skel) readline_tracker_bpf__destroy(skel);
    if (g_tcp_socket != -1) {
        printf("Closing TCP connection to %s:%d\n", g_tcp_remote_host, TCP_REMOTE_PORT);
        close(g_tcp_socket);
        g_tcp_socket = -1;
    }
    printf("\nExiting.\n");
    return -err < 0 ? -err : 0;
}
