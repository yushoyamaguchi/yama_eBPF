from bcc import BPF
import time
import ctypes

# 定数定義
TRACEPOINT_NAME = "kvm:kvm_mmio"

# BPFプログラム
bpf_program = f"""
BPF_HASH(counter, u64, u64);

int trace_{TRACEPOINT_NAME.replace(':', '_')}(struct pt_regs *ctx) {{
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

# tracepointにアタッチ
b.attach_tracepoint(tp=TRACEPOINT_NAME, fn_name=f"trace_{TRACEPOINT_NAME.replace(':', '_')}")

# 前回の呼び出し回数を保持する変数
prev_count = 0

# 結果を出力
print(f"Tracing {TRACEPOINT_NAME}... Ctrl-C to end.")
try:
    while True:
        time.sleep(5)
        # カウンターの値を取得
        key = ctypes.c_ulong(0)
        try:
            val = b["counter"][key]
            diff = val.value - prev_count
            print(f"{TRACEPOINT_NAME} called {diff} times since last check")
            prev_count = val.value
        except KeyError:
            print(f"{TRACEPOINT_NAME} called 0 times since last check")
except KeyboardInterrupt:
    print("Tracing ended.")
