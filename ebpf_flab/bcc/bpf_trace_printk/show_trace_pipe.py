#!/usr/bin/python3

import sys

TRACE_PIPE = "/sys/kernel/debug/tracing/trace_pipe"

print("BPFのログを監視中... Ctrl+C で終了")

try:
    with open(TRACE_PIPE, "r") as f:
        while True:
            line = f.readline()
            if line:  # 空行を無視
                print(line.strip())
except KeyboardInterrupt:
    print("ログ監視を終了します。")
except PermissionError:
    print("エラー: trace_pipe にアクセスするためには root 権限が必要です。")
    sys.exit(1)
except FileNotFoundError:
    print("エラー: trace_pipe が見つかりません。BPF プログラムが正しくロードされているか確認してください。")
    sys.exit(1)
