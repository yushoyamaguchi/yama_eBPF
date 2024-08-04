from bcc import BPF
import time
import ctypes

# 定数定義
FUNCTION_NAME = "do_sys_open"

# BPFプログラム
bpf_program = f"""
BPF_HASH(counter, u64, u64);

int trace_{FUNCTION_NAME}(struct pt_regs *ctx) {{
    u64 key = 0;
    u64 *val;

    val = counter.lookup(&key);
    if (val) {{
        (*val)++;
    }} else {{
        u64 zero = 0;
        counter.update(&key, &zero);
    }}
    return 0;
}}
"""

# BPFコンパイラを初期化してBPFプログラムをロード
b = BPF(text=bpf_program)

# 関数にアタッチ
b.attach_kprobe(event=FUNCTION_NAME, fn_name=f"trace_{FUNCTION_NAME}")

# 結果を出力
print(f"Tracing {FUNCTION_NAME}... Ctrl-C to end.")
try:
    while True:
        time.sleep(1)
        # カウンターの値を取得
        key = ctypes.c_ulong(0)
        try:
            val = b["counter"][key]
            print(f"{FUNCTION_NAME} called {val.value} times")
        except KeyError:
            print(f"{FUNCTION_NAME} called 0 times")
except KeyboardInterrupt:
    print("Tracing ended.")
