#!/bin/bash

sudo apt update -y
sudo apt install preload tlp -y
sudo apt purge hexchat gnote drawing simple-scan transmission-gtk hypnotix mintwelcome ibus -y
sudo apt install fcitx fcitx-rime -y
sudo apt-get upgrade -y
sudo tee /etc/systemd/logind.conf <<<'KillUserProcesses=yes'
sudo tee /etc/modprobe.d/snd-hda-intel.conf <<<'options snd-hda-intel power_save=0'
sudo tee /etc/modprobe.d/modprobe.conf <<<'options snd-hda-intel model=,generic'
sudo sh -c 'echo 0 > /sys/module/snd_hda_intel/parameters/power_save'
sudo sh -c 'echo N > /sys/module/snd_hda_intel/parameters/power_save_controller'
sudo apt install nscd -y
sudo systemctl enable nscd
sudo systemctl start nscd
sudo touch /etc/apt/trusted.gpg 
sudo apt-get install ubuntu-restricted-addons -y 
sudo apt-get install ubuntu-restricted-extras -y 
sudo apt install resolvconf wireguard-dkms wireguard-tool
sudo apt-get install alsa-utils alsa-tools alsa-tools-gui alsamixergui -y
sudo swapoff -a
sudo rm -rf /swapfile
sudo bash -c "echo 'vm.swappiness = 0' >> /etc/sysctl.conf"
sudo echo 0 > /proc/sys/vm/swappiness
sudo apt --fix-broken install
sudo apt update -y
sudo apt upgrade -y
sudo apt autoremove -y
sudo apt autoclean -y
sudo apt purge -y
sudo apt-get install -f
