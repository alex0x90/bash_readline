# User-space application
APP_NAME      = readline_loader
# BPF object file (derived from BPF C file name)
BPF_OBJ_NAME  = readline_tracker.bpf.o
# BPF C source file
BPF_C_FILE    = readline_tracker.bpf.c
# Skeleton header file (e.g., program.skel.h, derived from BPF_C_FILE)
BPF_SKEL      = $(subst .bpf.c,,$(BPF_C_FILE)).skel.h

# Compiler and flags
CLANG         = clang
CC            = gcc
CFLAGS        = -g -Wall
# Static‐linker flags: -static plus all libbpf dependencies, including zstd and resolv
LDFLAGS       = -static -lbpf -ljson-c -lelf -lzstd -lz -lpthread -ldl -lresolv

# vmlinux.h location (assumes it's generated in the current directory)
VMLINUX_H     = ./vmlinux.h

.PHONY: all clean clean_vmlinux

all: $(APP_NAME)

# Rule to compile BPF C code to BPF object file
# Depends on the BPF C source and vmlinux.h
$(BPF_OBJ_NAME): $(BPF_C_FILE) $(VMLINUX_H)
	@echo "Compiling BPF code: $(BPF_C_FILE) -> $(BPF_OBJ_NAME)"
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/x86_64-linux-gnu \
		-c $(BPF_C_FILE) -o $(BPF_OBJ_NAME)

# Rule to generate BPF skeleton header
# Depends on the BPF object file
$(BPF_SKEL): $(BPF_OBJ_NAME)
	@echo "Generating BPF skeleton: $(BPF_OBJ_NAME) -> $(BPF_SKEL)"
	bpftool gen skeleton $(BPF_OBJ_NAME) > $(BPF_SKEL)

# Rule to compile user-space application (statically linked)
# Depends on the user-space C source and the generated BPF skeleton
$(APP_NAME): $(APP_NAME).c $(BPF_SKEL)
	@echo "Compiling user-space application (static): $(APP_NAME).c -> $(APP_NAME)"
	$(CC) $(CFLAGS) -static $(APP_NAME).c -o $(APP_NAME) $(LDFLAGS)

# Rule to generate vmlinux.h if it doesn't exist
$(VMLINUX_H):
	@echo "Checking for $(VMLINUX_H)..."
	@if [ ! -f "$(VMLINUX_H)" ]; then \
		echo "$(VMLINUX_H) not found. Attempting to generate..."; \
		if [ ! -f "/sys/kernel/btf/vmlinux" ]; then \
			echo "Error: /sys/kernel/btf/vmlinux not found. Cannot generate $(VMLINUX_H)."; \
			echo "Ensure your kernel has BTF enabled (CONFIG_DEBUG_INFO_BTF=y)."; \
			exit 1; \
		fi; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
		echo "Generated $(VMLINUX_H)"; \
	else \
		echo "$(VMLINUX_H) already exists."; \
	fi

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(APP_NAME) $(BPF_OBJ_NAME) $(BPF_SKEL)

# Target to explicitly clean vmlinux.h (use with caution, regeneration is slow)
clean_vmlinux:
	@echo "Cleaning vmlinux.h..."
	rm -f $(VMLINUX_H)
