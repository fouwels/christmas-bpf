/* SPDX-License-Identifier: GPL v2 */

/*

Parent Process
      |
      | fork() / clone()
      v
Child Process Created
      |
      |------------------ sched_process_fork -------------------> Fires here
      |   (child PID available)
      |
      | execve("/path/to/program")  // Child replaces its image
      v
New Program Loaded
      |
      |------------------ sys_enter_execve --------------------> Fires here
      |   (access to arguments)
      |
      | exec completes
      v
New Program Starts Running
      |
      |----------------- sched_process_exec -------------------> Fires here
      |   (new comm, PID, filename)
      v
Program Running Normally
*/

/*
user@localhost:~/w/bpf$ sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
name: sched_process_exec
ID: 242
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:__data_loc char[] filename;       offset:8;       size:4; signed:0;
        field:pid_t pid;        offset:12;      size:4; signed:1;
        field:pid_t old_pid;    offset:16;      size:4; signed:1;

print fmt: "filename=%s pid=%d old_pid=%d", __get_str(filename), REC->pid, REC->old_pid

user@localhost:~/w/bpf$ sudo bpftrace -l tracepoint:sched:sched_process_exec -v
tracepoint:sched:sched_process_exec
    __data_loc char[] filename
    pid_t pid
    pid_t old_pid
*/

/*
user@localhost:~/w/bpf$ sudo cat /sys/kernel/debug/tracing/events/sys_enter_execve/format
name: sys_enter_execve
ID: 850
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))

user@localhost:~/w/bpf$ sudo bpftrace -l tracepoint:syscalls:sys_enter_execve -v
tracepoint:syscalls:sys_enter_execve
    int __syscall_nr
    const char * filename
    const char *const * argv
    const char *const * envp
*/

// See https://kernel.googlesource.com/pub/scm/linux/kernel/git/nico/archive/+/v0.97/include/linux/errno.h for errno mapping

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf.h"

// Function to clear a message
static void zero_message(struct message *m)
{
    int i, j;

    // Clear scalar fields
    m->type = 0;
    m->err = 0;
    m->tgid = 0;
    m->ptgid = 0;
    m->len_arguments = 0;

    for (i = 0; i < STR_MAX_LENGTH; i++)
    {
        m->filename[i] = 0;
    }

    for (i = 0; i < EXEC_MAX_ARGUMENTS; i++)
    {
        for (j = 0; j < STR_MAX_LENGTH; j++)
        {
            m->arguments[i][j] = 0;
        }
    }
}

/*
tracepoint:sched:sched_process_exec
    __data_loc char[] filename
    pid_t pid
    pid_t old_pid
*/
SEC("tracepoint/sched/sched_process_exec")
int monitor_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct message *m; // output message
    struct task_struct *task;
    struct task_struct *real_parent;
    int error = 0;

    /// Set Up

    // allocate message
    m = bpf_ringbuf_reserve(&ringbuf, sizeof(struct message), 0);
    if (!m)
    {
        LOG_DEBUG("ringbuf reserve failed", "");
        // hard fail, we cannot get allocated a ringbus slot to send back any data
        return 0;
    }

    zero_message(m);

    // type
    m->type = SCHED_PROCESS_EXEC;

    /// Context Values

    // task file name
    u32 data_loc_filename = ctx->__data_loc_filename;
    u16 data_loc_filename_offset = data_loc_filename & 0xFFFF;
    u16 data_loc_filename_len = data_loc_filename >> 16; // length of filename

    if (data_loc_filename_len > sizeof(m->filename) - 1)
    {
        data_loc_filename_len = sizeof(m->filename) - 1;
    }

    error = bpf_probe_read_kernel_str(m->filename, data_loc_filename_len + 1, (&ctx->__data + data_loc_filename_offset));
    if (error < 0)
    {
        goto error;
    }

    /// Task Values

    task = (struct task_struct *)bpf_get_current_task();

    // task process pid (TGID)
    error = bpf_probe_read_kernel(&m->tgid, sizeof(m->tgid), &task->tgid);
    if (error < 0)
    {
        goto error;
    }

    // parent task
    error = bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
    if (error < 0)
    {
        goto error;
    }

    // parent task process pid (TGID)
    error = bpf_probe_read_kernel(&m->ptgid, sizeof(m->ptgid), &real_parent->tgid);
    if (error < 0)
    {
        goto error;
    }

error:

    if (error < 0)
        m->err = error;
    else
        m->err = 0;

    bpf_ringbuf_submit(m, 0);
    return 0;
}
/*
tracepoint:syscalls:sys_enter_execve
    int __syscall_nr
    const char * filename
    const char *const * argv
    const char *const * envp
*/
SEC("tracepoint/syscalls/sys_enter_execve")
int monitor_syscall_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct message *m; // output message
    struct task_struct *task;
    int error = 0;
    int i = 0;
    char *pointer = NULL;

    /// Set Up

    // allocate message
    m = bpf_ringbuf_reserve(&ringbuf, sizeof(struct message), 0);
    if (!m)
    {
        LOG_DEBUG("ringbuf reserve failed", "");
        // hard fail, we cannot get allocated a ringbus slot to send back any data
        return 0;
    }

    zero_message(m);

    // type
    m->type = SYS_ENTER_EXECVE;

    /// Context Values

    // syscall arguments
    // unsigned long *syscall_filename = ctx->args[0];

    char **syscall_argv = (char **)ctx->args[1]; // pointer to array of pointers to strings...
    // unsigned long *syscall_envp = ctx->args[2];

    for (i = 0; i < EXEC_MAX_ARGUMENTS; i++)
    {
        // follow pointer i to read string_pointer
        error = bpf_probe_read_user(&pointer, sizeof(pointer), &syscall_argv[i]);
        if (error < 0)
        {
            goto error;
        }
        if (!pointer)
        {
            break; // terminate at end
        }

        // read string at string_pointer
        error = bpf_probe_read_user_str(m->arguments[i], sizeof(m->arguments[i]), pointer);
        if (error < 0)
        {
            goto error;
        }

        m->len_arguments++;
    }

    /// Task Values
    task = (struct task_struct *)bpf_get_current_task();

    // task process pid (TGID)
    error = bpf_probe_read_kernel(&m->tgid, sizeof(m->tgid), &task->tgid);
    if (error < 0)
    {
        goto error;
    }

error:

    if (error < 0)
        m->err = error;
    else
        m->err = 0;

    bpf_ringbuf_submit(m, 0);
    return 0;
}

char _license[] SEC("license") = "GPL v2";
