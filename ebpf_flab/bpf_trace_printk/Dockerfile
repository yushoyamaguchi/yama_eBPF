FROM ubuntu:latest

# ビルドツールとヘッダをインストール
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    linux-libc-dev \
    pkg-config \
    vim
RUN rm -rf /var/lib/apt/lists/*

# appディレクトリを作成
RUN mkdir /app

WORKDIR /app

# ビルド
#RUN make libbpf-prog
