
#define DEBUG

// Define error codes for ourselves
#define STR_MAX_LENGTH 128    // max length we want to allocate per string
#define EXEC_MAX_ARGUMENTS 32 // max arguments we will read for a process

#define ERR_bpf_get_current_pid_tgid 20000001

#ifdef DEBUG
#define LOG_DEBUG(msg, arg)   \
    {                         \
        bpf_printk(msg, arg); \
    };
#else
#define LOG_DEBUG(msg, arg) {};
#endif

enum Type
{
    UNKNOWN,
    SCHED_PROCESS_EXEC,
    SYS_ENTER_EXECVE,
};

struct message
{
    s32 type;
    s32 err;
    s32 tgid;
    s32 ptgid;
    u8 filename[STR_MAX_LENGTH];
    u8 arguments[EXEC_MAX_ARGUMENTS][STR_MAX_LENGTH];
    u32 len_arguments;
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); // bytes
} ringbuf SEC(".maps");