# bpf_trace_printk で出力した文字列を確認する
/sys/kernel/debug/tracing/trace_pipe というファイルの中身を見る

# フックポイント
BPFプログラムのエントリ関数の前で宣言する、SEC()の中にフックポイントのタイプを記述