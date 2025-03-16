#!/usr/bin/python3
from bcc import BPF

# BPFプログラム
bpf_program = """
int hello_world(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# BPFプログラムをコンパイル・ロード
b = BPF(text=bpf_program)

# execve 系の kprobe/tracepoint にアタッチ
try:
    b.attach_kprobe(event="__x64_sys_execve", fn_name="hello_world")
    print("__x64_sys_execve にアタッチしました")
except Exception:
    try:
        b.attach_kprobe(event="do_execve", fn_name="hello_world")
        print("do_execve にアタッチしました")
    except Exception:
        try:
            b.attach_kprobe(event="exec_binprm", fn_name="hello_world")
            print("exec_binprm にアタッチしました")
        except Exception:
            try:
                b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="hello_world")
                print("tracepoint sched:sched_process_exec にアタッチしました")
            except Exception as e:
                print("エラー: kprobe/tracepoint をアタッチできませんでした")
                print(f"エラー詳細: {e}")
                exit(1)

print("BPFプログラムをロードしました。")
print("このスクリプトを実行したままにし、別のスクリプトでログを読み取ってください。")

# プログラムを継続実行 (終了しないように)
try:
    while True:
        pass
except KeyboardInterrupt:
    print("BPFプログラムを終了します。")
