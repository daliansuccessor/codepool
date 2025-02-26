#!/bin/bash

# 确保以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请以 root 用户运行此脚本！"
    exit 1
fi

LOG_FILE="/var/log/setup_server.log"
exec > >(tee -i $LOG_FILE) 2>&1

# 安装 WireGuard 使用指定脚本
# Installing Wireguard. Code source: https://github.com/angristan/wireguard-install/blob/master/wireguard-install.sh
function install_wireguard() {
    echo "安装 wireguard..."
    wget https://raw.githubusercontent.com/angristan/wireguard-install/refs/heads/master/wireguard-install.sh
    chmod +x wireguard-install.sh
    bash wireguard-install.sh
}

# 安装必要的软件包
function install_dependencies() {
    echo "安装必要的软件包..."
    apt install -y cpufrequtils iptables haveged nscd qrencode nginx
}

# 启用 cpufrequtils
function enable_cpufrequtils() {
    echo "启用 cpufrequtils..."
    sudo cpufreq-set -r -g performance
}

# 设置时区
function set_timezone() {
    echo "设置时区为 Asia/Hong_Kong..."
    timedatectl set-timezone Asia/Hong_Kong
}

# 启用并启动 nscd 服务
function enable_nscd() {
    echo "启用并启动 nscd 服务..."
    systemctl enable nscd && systemctl start nscd
}

# 配置 iptables 优化 TCP 性能
function optimize_tcp() {
    echo "优化 TCP 性能..."
    iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}

# 启用 haveged 服务
function enable_haveged() {
    echo "启用 haveged 服务..."
    sudo systemctl enable --now haveged
}

# 写入内核参数优化配置到 /etc/sysctl.conf
function optimize_sysctl() {
    echo "优化内核参数..."
    cat >> /etc/sysctl.conf <<EOF

# 优化 TCP 和 UDP 性能
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_max_syn_backlog=40960
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

# 针对 UDP（QUIC 和 WireGuard）的优化
net.core.rmem_max=167772160
net.core.wmem_max=167772160
net.core.rmem_default=83886080
net.core.wmem_default=83886080
net.core.netdev_max_backlog=100000
net.core.optmem_max=655360
net.ipv4.udp_mem=2097152 4194304 8388608
net.ipv4.udp_rmem_min=5819200
net.ipv4.udp_wmem_min=5819200

# 针对 IPv6 的优化
net.ipv6.conf.all.disable_ipv6=0
net.ipv6.conf.default.disable_ipv6=0
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.accept_ra=2
net.ipv6.conf.default.accept_ra=2
net.ipv6.conf.all.autoconf=1
net.ipv6.conf.default.autoconf=1

# 文件描述符限制
fs.file-max=512000
fs.nr_open=10485760

# 系统资源限制
vm.swappiness=0
vm.dirty_ratio=20
vm.dirty_background_ratio=10

# 默认队列规则和拥塞控制算法
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -p
}

# 启用 IP 转发（IPv4 和 IPv6）
function enable_ip_forwarding() {
    echo "启用 IP 转发..."
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
    sysctl -p
}

# 配置 iptables 转发规则（IPv4 和 IPv6）
function configure_iptables() {
    echo "配置 iptables，将所有 20000 以上的 UDP 流量转发到端口 9999..."
    iptables -t nat -A PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-port 9999
    ip6tables -t nat -A PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-port 9999
}

# 配置 fq_pie 队列规则
function configure_fq_pie() {
    echo "配置 fq_pie 队列规则..."
    tc qdisc add dev wg0 root fq_pie
    tc qdisc add dev ens5 root fq_pie
    tc qdisc add dev eth0 root fq_pie
}

# 配置系统日志限制
function configure_journald() {
    echo "配置系统日志限制..."
    cat > /etc/systemd/journald.conf <<EOF
[Journal]
SystemMaxUse=384M
SystemMaxFileSize=128M
ForwardToSyslog=no
EOF
    systemctl restart systemd-journald
}

# 配置打开文件描述符限制
function configure_open_file_limits() {
    echo "配置打开文件描述符限制..."
    cat > /etc/security/limits.conf <<EOF
* soft nofile 512000
* hard nofile 512000
* soft nproc 512000
* hard nproc 512000
root soft nofile 512000
root hard nofile 512000
root soft nproc 512000
root hard nproc 512000
EOF
}

# 新增 TCP 优化功能
function optimize_tcp_settings() {
    echo "优化 TCP 设置..."
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0
    sysctl -w net.ipv4.tcp_ecn=1
}

# 脚本运行完成后重启服务器
function reboot_server() {
    echo "脚本运行完成，重启服务器..."
    reboot
}

# 主函数调用所有功能
function main() {
    install_wireguard
    install_dependencies
    enable_cpufrequtils
    set_timezone
    enable_nscd
    optimize_tcp
    enable_haveged
    optimize_sysctl
    enable_ip_forwarding
    configure_iptables
    configure_fq_pie
    configure_journald
    configure_open_file_limits
    optimize_tcp_settings
    reboot_server
}

# 执行主函数
main
