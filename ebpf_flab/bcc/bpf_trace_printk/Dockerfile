FROM ubuntu:22.04

# タイムゾーンの設定（インタラクティブな質問を避けるため）
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Tokyo

# 必要なパッケージのインストール
RUN apt-get update
RUN apt-get install -y \
    python3 \
    python3-pip \
    bpfcc-tools \
    linux-tools-generic \
    linux-cloud-tools-generic \
    linux-headers-generic \
    build-essential \
    git \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    kmod

RUN rm -rf /var/lib/apt/lists/*

# BCCをPythonからインストール
RUN pip3 install bcc

# 作業ディレクトリの作成
WORKDIR /app

# スクリプトをコンテナ内にコピー
COPY check_execv.py /app/