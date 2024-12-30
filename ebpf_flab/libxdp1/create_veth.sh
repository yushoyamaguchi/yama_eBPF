#!/bin/bash

# ハードコーディングされた設定
NAMESPACE="mynamespace"
VETH_A="veth-a"
VETH_B="veth-b"
IP_A="192.168.1.1/24"
IP_B="192.168.1.2/24"

# ネットワーク名前空間が存在しない場合は作成する
if ! ip netns list | grep -q "^$NAMESPACE$"; then
    echo "Creating namespace: $NAMESPACE"
    ip netns add $NAMESPACE
else
    echo "Namespace $NAMESPACE already exists."
fi

# 既存の veth を削除（必要な場合）
ip link delete $VETH_A type veth 2>/dev/null || true

# veth ペアを作成
echo "Creating veth pair: $VETH_A and $VETH_B"
ip link add $VETH_A type veth peer name $VETH_B

# 一方の veth を名前空間に移動
echo "Moving $VETH_B to namespace $NAMESPACE"
ip link set $VETH_B netns $NAMESPACE

# ホスト側の veth にIPアドレスを設定して有効化
echo "Configuring $VETH_A with IP $IP_A"
ip addr add $IP_A dev $VETH_A
ip link set $VETH_A up

# 名前空間内で veth にIPアドレスを設定して有効化
echo "Configuring $VETH_B with IP $IP_B inside namespace $NAMESPACE"
ip netns exec $NAMESPACE ip addr add $IP_B dev $VETH_B
ip netns exec $NAMESPACE ip link set $VETH_B up

# 確認
echo "veth pair setup complete:"
echo "  Host side: $VETH_A ($IP_A)"
echo "  Namespace side: $VETH_B ($IP_B in $NAMESPACE)"
