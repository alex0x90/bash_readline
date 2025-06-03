# Bash readline monitor app

A small eBPF CO-RE tracer app that hooks into Bash`s readline() function the output save into /tmp/Output.log or could be sent to remote host.
This project demonstrates how to:
- Compile a BPF program (readline_tracker.bpf.c) against the kernel’s BTF (vmlinux.h).
- Generate a libbpf skeleton header (readline_tracker.skel.h).
- Build a standalone, static user‐space loader (readline_loader) that attaches the BPF program to Bash. 

##  Usage: sudo ./readline_loader [options]
 Options:
   -h, --help                Show this help message
   -t, --tcp-server <host>   Send output via TCP to <host> on port 8080
   -n, --no-file             Do not write output to the local JSON file
   -o, --output-file <FILE>  Specify a different local output file (default: /tmp/Output.log)

Kernel version 4.12 and upper

# Architecture

![image](https://github.com/user-attachments/assets/24f6ed1d-7a7b-4558-a6fb-ab5531c0f135)

