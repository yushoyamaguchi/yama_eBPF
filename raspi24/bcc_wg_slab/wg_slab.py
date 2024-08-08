#!/usr/bin/python
from bcc import BPF
from time import sleep

# BPFプログラム定義
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// カウンター用のマップ定義
BPF_HASH(alloc_counts, u32, u64);  // PID -> alloc count
BPF_HASH(free_counts, u32, u64);   // PID -> free count

static inline bool is_kworker(char *comm) {
    char wg[] = "kworker";

    // comm に "kworker" を含むか確認
    for (int i = 0; i <= TASK_COMM_LEN - sizeof(wg) + 1; i++) {
        bool found = true;
        for (int j = 0; j < sizeof(wg) - 1; j++) {
            if (comm[i + j] != wg[j]) {
                found = false;
                break;
            }
        }
        if (found) return true;
    }

    return false;
}

// kmem_cache_alloc()の監視
int trace_kmem_alloc(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // kworkerのみを対象
    if (!is_kworker(comm))
        return 0;

    u64 *count = alloc_counts.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        alloc_counts.update(&pid, &init_val);
    }
    return 0;
}

// kmem_cache_free()の監視
int trace_kmem_free(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // kworkerプロセスのみを対象
    if (!is_kworker(comm))
        return 0;

    u64 *count = free_counts.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        free_counts.update(&pid, &init_val);
    }
    return 0;
}
"""

# BPFプログラムのロードと初期化
b = BPF(text=bpf_text)

# カーネル関数にkprobeをアタッチ
b.attach_kprobe(event="kmem_cache_alloc", fn_name="trace_kmem_alloc")
b.attach_kprobe(event="kmem_cache_free", fn_name="trace_kmem_free")

print("Tracing kmem_cache allocations for WireGuard processes... Ctrl+C to end.")

# 結果表示用の関数
def print_stats():
    print("\n%-6s %-16s %-10s %-10s" % ("PID", "COMM", "ALLOCS", "FREES"))
    for k, v in sorted(b["alloc_counts"].items(), key=lambda item: item[0].value):
        pid = k.value
        alloc_count = v.value
        free_count = b["free_counts"][k].value if k in b["free_counts"] else 0
        try:
            comm = open(f"/proc/{pid}/comm", "r").read().strip()
            print("%-6d %-16s %-10d %-10d" % (pid, comm, alloc_count, free_count))
        except:
            # プロセスが終了している場合はスキップ
            continue


# メインループ
try:
    while True:
        sleep(2)
        print_stats()
except KeyboardInterrupt:
    print_stats()
    print("Detaching...")