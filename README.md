# Bash readline monitor app

A small eBPF CO-RE tracer app that hooks into Bash`s readline() function the output save into /tmp/Output.log or could be sent to remote host.<br>
This project demonstrates how to:<br>
- Compile a BPF program (readline_tracker.bpf.c) against the kernel’s BTF (vmlinux.h).<br>
- Generate a libbpf skeleton header (readline_tracker.skel.h).<br>
- Build a standalone, static user‐space loader (readline_loader) that attaches the BPF program to Bash. <br>

```
Usage: sudo ./readline_loader [options]<br>
Options:
		-h, --help                Show this help message<br>
		-t, --tcp-server <host>   Send output via TCP to <host> on port 8080<br>
		-n, --no-file             Do not write output to the local JSON file<br>
		-o, --output-file <FILE>  Specify a different local output file (default: /tmp/Output.log)<br>
```
*Kernel version 4.12 and upper<br>

# Architecture

![image](https://github.com/user-attachments/assets/24f6ed1d-7a7b-4558-a6fb-ab5531c0f135)

