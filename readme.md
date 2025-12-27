Holiday experiments in eBPF syscall/exec monitoring

- ./bpf for the c kernel code
- ./bin for the go userspace code 

make targets to build with LLVM and load

- ./bpf (kernel) is GPL v2, as this is enforced by the verifier
- ./bin (userspace) is MIT, go wild

goto error conditions are non-harmful
