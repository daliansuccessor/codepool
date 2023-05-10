#!/bin/bash
sudo timedatectl set-timezone Asia/Hong_Kong
echo root:TANcheng570827 |sudo chpasswd root
sudo sed -i 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
sudo sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo service sshd restart
systemctl stop firewalld.service
systemctl disable firewalld.service
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
echo "net.ipv4.tcp_fastopen=3" >> /etc/sysctl.conf
sysctl -p
lsmod | grep bbr
sudo modprobe tcp_bbr
echo "tcp_bbr" | sudo tee --append /etc/modules-load.d/modules.conf
echo "net.core.default_qdisc=fq" | sudo tee --append /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee --append /etc/sysctl.conf
sudo sysctl -p
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_congestion_control
lsmod | grep bbr
echo '* - nofile 65535 ' >>/etc/security/limits.conf
echo "* soft nproc 65535" >> /etc/security/limits.conf
echo "* hard nproc 65535" >> /etc/security/limits.conf
echo "* soft nproc 65535" >> /etc/security/limits.d/20-nproc.conf
yum install nscd -y;
systemctl enable nscd;
systemctl start nscd;
reboot
