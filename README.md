# bash readline monitor app

A small eBPF CO-RE tracer app that hooks into Bash`s readline() function the output save into /tmp/Output.log or could be sent to remote host.
This project demonstrates how to:
- Compile a BPF program (readline_tracker.bpf.c) against the kernel’s BTF (vmlinux.h).
- Generate a libbpf skeleton header (readline_tracker.skel.h).
- Build a standalone, static user‐space loader (readline_loader) that attaches the BPF program to Bash. 
Usage:
![image](https://github.com/user-attachments/assets/3bb62677-5380-4270-9849-165753fac6b0)
