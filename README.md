# bash_readline app

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Bash Process  │    │   eBPF Program   │    │ Userspace App   │
│                 │    │   (Kernel)       │    │                 │
│  readline() ────┼───▶│ uprobe hook ─────┼───▶│ Event handler   │
│                 │    │                  │    │                 │
│                 │    │ Ring buffer ─────┼───▶│ Log file writer │
└─────────────────┘    └──────────────────┘    └─────────────────┘
