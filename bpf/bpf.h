// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: 2024 Kaelan Thijs Fouwels <kaelan.thijs@fouwels.com>

// Toggle on our own debug mode
#define USR_DEBUG

// Define error codes for ourselves
#define STR_MAX_LENGTH 128    // max length we want to allocate per string
#define EXEC_MAX_ARGUMENTS 32 // max arguments we will read for a process

#ifdef USR_DEBUG
// Writes to trace log, see makefile util-trace for reading
#define LOG_DEBUG(msg, arg)   \
    {                         \
        bpf_printk(msg, arg); \
    };
#else
#define LOG_DEBUG(msg, arg) {};
#endif

// message type to userspace
enum Type
{
    UNKNOWN,
    SCHED_PROCESS_EXEC,
    SYS_ENTER_EXECVE,
    SYS_ENTER_EXECVEAT,
};

// output message to user space
struct message
{
    s32 type;
    s32 err;
    s32 task_tgid;
    s32 task_ptgid;
    u8 filename[STR_MAX_LENGTH];
    u8 arguments[EXEC_MAX_ARGUMENTS][STR_MAX_LENGTH];
    u32 len_arguments;
};

// bpf magic struct defining ring buffer
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); // bytes
} ringbuf SEC(".maps");
