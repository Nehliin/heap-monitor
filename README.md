# Experiment using eBPF programs written in rust

This repo contains a cli tool that can help monitor heap usage by loading eBPF probes that monitors `malloc`, `calloc`, `free` and `realloc` calls in `libc` for a given process. The data is then processed by the cli and a list of the largest allocations produced by a given stack trace that hasn't yet been freed will be presented when the monitoring is ended.

For it to be useful the process that the cli is attached to must be compiled with `-fno-omit-frame-pointer` or equivalent option.


Did this as a bit of a side project to learn symbolication and eBPF:s a bit better so expect issues since there a bunch of TODO:s left in the code. Lost a bit of the motivation for the project so cleaned it up a bit to make it useful at least.

Example:

```bash
cargo build --release && sudo ./target/release/heap-monitor --pid $(pidof <program>)
```

![Example output](https://media.giphy.com/media/lGXdRw58g7WpafM6i1/giphy.gif)