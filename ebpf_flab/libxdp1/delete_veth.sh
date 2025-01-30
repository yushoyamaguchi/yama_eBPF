#!/bin/bash

# ハードコーディングされた設定
NAMESPACE="mynamespace"
VETH_A="veth-a"

# ネットワーク名前空間の削除
if ip netns list | grep -q "^$NAMESPACE$"; then
    echo "Deleting namespace: $NAMESPACE"
    ip netns del $NAMESPACE
else
    echo "Namespace $NAMESPACE does not exist."
fi

# veth ペアの削除
if ip link show $VETH_A >/dev/null 2>&1; then
    echo "Deleting veth pair: $VETH_A"
    ip link delete $VETH_A type veth
else
    echo "veth pair $VETH_A does not exist."
fi

echo "Cleanup complete."
