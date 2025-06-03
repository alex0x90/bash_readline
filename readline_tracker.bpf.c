// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define OUTPUT_STR_LEN 480

// Define a structure to hold the data sent to user space
struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char str[OUTPUT_STR_LEN];
};

// Define the perf event array map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 128); // Max CPUs, adjust if needed
} events SEC(".maps");

// uretprobe for the readline function in /bin/bash
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, void *ret) {
    struct data_t data = {};
    u64 id;

    // If readline returns NULL, ret (which is ctx->ax) will be 0.
    if (!ret) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read the string returned by readline
    // PT_REGS_RC(ctx) is a common way to get return value, but for uretprobe,
    // the 'ret' argument to BPF_KRETPROBE already holds it.
    // Make sure to use bpf_probe_read_user_str for user-space strings.
    bpf_probe_read_user_str(&data.str, sizeof(data.str), (const char *)ret);

    // Submit data to user space via perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
