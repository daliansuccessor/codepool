#!/bin/bash

# 确保以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请以 root 用户运行此脚本！"
    exit 1
fi

# 设置时区为 Asia/Hong_Kong
echo "设置时区为 Asia/Hong_Kong..."
sudo timedatectl set-timezone Asia/Hong_Kong

# 系统更新和优化
echo "更新系统并修复依赖..."
sudo apt --fix-broken install -y
sudo apt update -y
sudo apt full-upgrade -y
sudo apt autoremove -y
sudo apt autoclean -y
sudo apt purge -y
sudo apt-get install -f -y

# 安装必要的软件包
echo "安装必要的软件包..."
sudo apt install -y indicator-cpufreq iptables haveged nscd wireguard qrencode nginx

# 启用并启动 nscd 服务
echo "启用并启动 nscd 服务..."
sudo systemctl enable nscd
sudo systemctl start nscd

# 配置 iptables 优化 TCP 性能
echo "优化 TCP 性能..."
sudo iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# 启用 haveged 服务
echo "启用 haveged 服务..."
sudo systemctl enable --now haveged

# 启用 BBR 拥塞控制算法
echo "启用 BBR 拥塞控制算法..."
sudo echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
sudo echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sudo sysctl -p
sudo sysctl net.ipv4.tcp_available_congestion_control

# 创建密钥对目录
echo "生成服务器和客户端的密钥对..."
mkdir -p /etc/wireguard/keys
chmod 700 /etc/wireguard/keys

# 生成服务器密钥对
wg genkey | tee /etc/wireguard/keys/server_private.key | wg pubkey > /etc/wireguard/keys/server_public.key
SERVER_PRIVATE_KEY=$(cat /etc/wireguard/keys/server_private.key)
SERVER_PUBLIC_KEY=$(cat /etc/wireguard/keys/server_public.key)

# 配置客户端数量
CLIENT_COUNT=10
CLIENT_CONFIG_DIR="/etc/wireguard/clients"
mkdir -p $CLIENT_CONFIG_DIR

# 初始化客户端配置数组
CLIENT_PRIVATE_KEYS=()
CLIENT_PUBLIC_KEYS=()
CLIENT_IPS_IPV4=()
CLIENT_IPS_IPV6=()

# 为每个客户端生成密钥对和 IP 地址
for i in $(seq 1 $CLIENT_COUNT); do
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)

    CLIENT_PRIVATE_KEYS+=($CLIENT_PRIVATE_KEY)
    CLIENT_PUBLIC_KEYS+=($CLIENT_PUBLIC_KEY)

    # 分配 IPv4 和 IPv6 地址
    CLIENT_IP_IPV4="172.16.0.$((i + 1))"
    CLIENT_IP_IPV6="fd00:172:16::$((i + 1))"

    CLIENT_IPS_IPV4+=($CLIENT_IP_IPV4)
    CLIENT_IPS_IPV6+=($CLIENT_IP_IPV6)
done

# 配置 WireGuard 服务端
echo "配置 WireGuard 服务端..."
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 172.16.0.1/24, fd00:172:16::1/64
ListenPort = 9999
SaveConfig = true

# 防火墙规则
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

# 为每个客户端添加 Peer 配置
for i in $(seq 1 $CLIENT_COUNT); do
    cat >> /etc/wireguard/wg0.conf <<EOF

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEYS[$((i - 1))]}
AllowedIPs = ${CLIENT_IPS_IPV4[$((i - 1))]}/32, ${CLIENT_IPS_IPV6[$((i - 1))]}/128
EOF
done

chmod 600 /etc/wireguard/wg0.conf

# 启用 IP 转发（IPv4 和 IPv6）
echo "启用 IP 转发..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
sysctl -p

# 配置防火墙
echo "配置防火墙..."
ufw allow 9999/udp
ufw reload

# 配置 iptables 转发规则（IPv4 和 IPv6）
echo "配置 iptables，将所有 20000 以上的 UDP 流量转发到端口 9999..."
iptables -t nat -A PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-port 9999
ip6tables -t nat -A PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-port 9999

# 启动 WireGuard
echo "启动 WireGuard..."
wg-quick up wg0
systemctl enable wg-quick@wg0

# 生成客户端配置文件
echo "生成客户端配置文件..."
for i in $(seq 1 $CLIENT_COUNT); do
    CLIENT_CONFIG_FILE="$CLIENT_CONFIG_DIR/client$i-wg0.conf"
    cat > $CLIENT_CONFIG_FILE <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEYS[$((i - 1))]}
Address = ${CLIENT_IPS_IPV4[$((i - 1))]}/24, ${CLIENT_IPS_IPV6[$((i - 1))]}/64
DNS = dot.sb

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = [$(curl -s ifconfig.me)]:9999
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    echo "客户端 $i 配置文件已生成：$CLIENT_CONFIG_FILE"
    qrencode -t ansiutf8 < $CLIENT_CONFIG_FILE
    echo "可以使用 WireGuard 客户端扫描上面的二维码导入配置。"
done

# 配置 Nginx
echo "配置 Nginx，将 HTTP 请求跳转到 https://visa.com..."
cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    location / {
        return 301 https://visa.com;
    }
}
EOF

# 重启 Nginx 服务
echo "重启 Nginx 服务..."
systemctl restart nginx

# 配置 fq_pie 队列规则
echo "配置 fq_pie 队列规则..."
tc qdisc add dev wg0 root fq_pie 2>/dev/null || echo "警告：无法为 wg0 配置 fq_pie，可能设备未启用"
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}')
tc qdisc add dev $DEFAULT_INTERFACE root fq_pie 2>/dev/null || echo "警告：无法为 $DEFAULT_INTERFACE 配置 fq_pie，可能设备未启用"

echo "WireGuard 和 Nginx 安装与配置完成！"
