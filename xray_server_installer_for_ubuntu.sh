#!/bin/bash

TMP_DIR="/tmp"

Add_To_New_Line(){
	if [ "$(tail -n1 $1 | wc -l)" == "0"  ];then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

Check_And_Add_Line(){
	if [ -z "$(cat "$1" | grep "$2")" ];then
		Add_To_New_Line "$1" "$2"
	fi
}

get_my_ip(){
	local my_ip=$(ifconfig | grep "inet" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed -n 1p)
	echo $my_ip
}

Update_Upgrade_Packages(){
	echo "#############################################"
	echo "Update Packages..."
	apt update
	apt upgrade -y
	apt dist-upgrade -y
	apt autoremove -y
	apt autoclean -y
	echo "Update Packages Done."
	if [ -f /var/run/reboot-required ];then 
		echo "Will Reboot in 5s!!!"
		sleep 5
		reboot
	fi
	echo "Install Packages Done."
	echo "#############################################"
}

Install_Bin(){
	wget https://github.com/freakinyy/xray_server_installer_for_ubuntu/edit/main/xray_bin_installer.sh%4064 -O xray_bin_installer.sh
	cp xray_bin_installer.sh /usr/bin
	chmod +x /usr/bin/xray_bin_installer.sh
	xray_bin_installer.sh install
}

Uninstall_Bin(){
	xray_bin_installer.sh uninstall
	rm -f /usr/bin/xray_bin_installer.sh
}

Install_Rng_tools(){
	echo "#############################################"
	echo "Install Rng-tools..."
	apt install --no-install-recommends virt-what -y
	echo "Your Virtualization type is $(virt-what)"
	if [ "$(virt-what)" != "kvm" -a "$(virt-what)" != "hyperv" ];then
		echo "Rng-tools can not be used."
		echo "#############################################"
		return 1
	fi
	apt install rng-tools -y
	Check_And_Add_Line "/etc/default/rng-tools" "HRNGDEVICE=/dev/urandom"
	service rng-tools stop
	service rng-tools start
	echo "Install Rng-tools Done."
	echo "#############################################"
}

Install_BBR(){
	echo "#############################################"
	echo "Install TCP_BBR..."
	if [ -n "$(lsmod | grep bbr)" ];then
		echo "TCP_BBR already installed."
		echo "#############################################"
		return 1
	fi
	local kernel_version=$(uname -r | grep -oE '[0-9]\.[0-9]' | sed -n 1p)
	local can_use_BBR="0"
	if [ "echo $kernel_version | cut -d"." -f1" > "4" ];then
		can_use_BBR="1"
	elif [ "echo $kernel_version | cut -d"." -f1" == "4" ];then
		if [ "echo $kernel_version | cut -d"." -f2" >= "9" ];then
			can_use_BBR="1"
		fi
	fi
	if [ "$can_use_BBR" == "1" ];then
		echo "Your Kernel Version $(uname -r) >= 4.9"
	else
		echo "Your Kernel Version $(uname -r) < 4.9"
		echo "TCP_BBR can not be used."
		echo "#############################################"
		return 1
	fi
	apt install --no-install-recommends virt-what -y
	echo "Your Virtualization type is $(virt-what)"
	if [ "$(virt-what)" != "kvm"  && "$(virt-what)" != "hyperv" ];then
		echo "TCP_BBR can not be used."
		echo "#############################################"
		return 1
	fi
	echo "TCP_BBR can be used."
	echo "Start to Install TCP_BBR..."
	modprobe tcp_bbr
	Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
	Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
	Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
	sysctl -p
	if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ];then
		echo "TCP_BBR Install Success."
	else
		echo "Fail to Install TCP_BBR."
	fi
	echo "#############################################"
}

Optimize_Parameters(){
	echo "#############################################"
	echo "Optimize Parameters..."
	Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 51200"
	Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 51200"
	Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
	Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_all = 1"
	Check_And_Add_Line "/etc/sysctl.conf" "fs.file-max = 51200"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_max_backlog = 250000"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn = 4096"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_syncookies = 1"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse = 1"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_recycle = 0"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout = 30"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time = 1200"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_local_port_range = 10000 65000"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 8192"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets = 5000"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fastopen = 3"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mem = 25600 51200 102400"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rmem = 4096 87380 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_wmem = 4096 65536 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing = 1"
	echo "Optimize Parameters Done."
	echo "#############################################"
}

Create_Json(){
	echo "#############################################"
	echo "Create json path and file..."
	if [ -d /etc/xray_server/ ];then
		json_files=$(ls /etc/xray_server/ | grep ".json$" )
		if [ -n "$json_files" ];then
			echo "Json path and file already exit, abort."
			echo "#############################################"
			return 1
		else
			rm -rf /etc/xray_server/
		fi
	fi
	mkdir -p /etc/xray_server/
	local key_pair=$(xray x25519)
	local private_key=$(echo $key_pair | sed -n 1p | cut -d " " -f3)
	local public_key=$(echo $key_pair | sed -n 2p | cut -d " " -f3)
	apt install openssl -y
	local short_id=$(openssl rand -hex 8)
	local uuid=$(xray uuid)
	touch /etc/xray_server/vless_reality.json
	cat >> /etc/xray_server/vless_reality.json <<EOF
{
	"log": {
		"access": "none",
		"error": "/var/log/xray_server/vless_reality.log",
		"loglevel": "warning",
		"dnsLog": false
	},
	"inbounds": [
		{
			"protocol": "vless",
			"tag": "in-vless",
			"listen": "::",
			"port": 443,
			"settings": {
				"clients": [
					{
						"id": "$uuid",
						"flow": "xtls-rprx-vision"
					}
				],
				"decryption": "none"
			},
			"streamSettings": {
				"network": "tcp",
				"security": "reality",
				"realitySettings": {
					"show": false,
					"dest": "www.amazon.com:443",
					"xver": 0,
					"serverNames": [
						"www.amazon.com"
					],
					"privateKey": "$private_key",
					"maxTimeDiff": 60000,
					"shortIds": [
						"$short_id"
					],
					"fingerprint": "chrome"
				}
			}
		}
	],
	"outbounds": [
		{
			"protocol": "freedom",
			"tag": "out-freedom"
		}
	]
}
EOF
	echo "Create json path and file Done."
	echo "#############################################"
	Show_Client_Outbound $public_key $short_id $uuid
}

Show_Client_Outbound(){
	echo "#############################################"
	echo "Your client outbound should be:"
	local public_key=$1
	local short_id=$2
	local uuid=$3
	local server=$(get_my_ip)
	cat << EOF
{
	"type": "vless",
	"tag": "out-vless",
	"server": "$server",
	"server_port": 443,
	"uuid": "$uuid",
	"flow": "xtls-rprx-vision",
	"tls": {
		"enabled": true,
		"disable_sni": false,
		"server_name": "www.amazon.com",
		"insecure": false,
		"utls": {
			"enabled": true,
			"fingerprint": "chrome"
		},
		"reality": {
			"enabled": true,
			"public_key": "$public_key",
			"short_id": "$short_id"
		}
	},
	"packet_encoding": "xudp"
}
EOF
	echo "#############################################"
}

Remove_Json(){
	echo "#############################################"
	echo "Remove json path and file..."
	rm -rf /etc/xray_server/
	echo "Remove json path and file Done."
	echo "#############################################"
}

Create_Service(){
	echo "#############################################"
	echo "Create Service..."
	if [ -f /etc/init.d/xray_server ];then
		service xray_server stop
		update-rc.d -f xray_server remove
		rm -f /etc/init.d/xray_server
	fi
	wget https://github.com/freakinyy/xray_server_installer_for_ubuntu/raw/main/xray_server.service%40ubuntu -O xray_server.service@ubuntu
	cp xray_server.service@ubuntu /etc/init.d/xray_server
	chmod +x /etc/init.d/xray_server
	update-rc.d -f xray_server defaults 95
	echo "Create Service Done."
	echo "#############################################"
}

Remove_Service(){
	echo "#############################################"
	echo "Remove Service..."
	service xray_server stop
	update-rc.d -f xray_server remove
	rm -f /etc/init.d/xray_server
	echo "Remove Service Done."
	echo "#############################################"
}

Add_to_Crontab(){
	echo "#############################################"
	echo "Add updates-and-upgrades to crontab, you should modify these items and their schedules at your own favor..."
	rm -f $TMP_DIR/crontab.bak
	touch $TMP_DIR/crontab.bak
	crontab -l >> $TMP_DIR/crontab.bak
	
	local start_line_num=$(grep -n "#xray_server modifies start" $TMP_DIR/crontab.bak | cut -d":" -f1)
	local end_line_num=$(grep -n "#xray_server modifies end" $TMP_DIR/crontab.bak | cut -d":" -f1)
	if [ -n "$start_line_num" ] || [ -n "$end_line_num" ];then
		echo "It seems that crontab has already modified by this scprit, abort."
		echo "Please Check Crontab!!!"
		echo "#############################################"
		return 1
	fi
	
	cat >> $TMP_DIR/crontab.bak <<EOF
#xray_server modifies start
55 04 * * * xray_bin_installer.sh update
#xray_server modifies end
EOF
	crontab $TMP_DIR/crontab.bak
	echo "Add updates-and-upgrades to crontab Done."
	echo "#############################################"
}

Remove_from_Crontab(){
	echo "#############################################"
	echo "Remove updates-and-upgrades from crontab..."
	rm -f $TMP_DIR/crontab.bak
	touch $TMP_DIR/crontab.bak
	crontab -l >> $TMP_DIR/crontab.bak
	local start_line_num=$(grep -n "#xray_server modifies start" $TMP_DIR/crontab.bak | cut -d":" -f1)
	local end_line_num=$(grep -n "#xray_server modifies end" $TMP_DIR/crontab.bak | cut -d":" -f1)
	[ -n "$start_line_num" ] && [ -n "$end_line_num" ] && sed -i ''"$start_line_num"','"$end_line_num"'d' $TMP_DIR/crontab.bak
	crontab $TMP_DIR/crontab.bak
	echo "Remove updates-and-upgrades from crontab Done."
	echo "#############################################"
}

Do_Install(){
	echo "#########################################################################"
	echo "Start Install xray_server..."
	service xray_server stop
	Update_Upgrade_Packages
	Install_Bin
	Create_Json
	Create_Service
	Add_to_Crontab
	service xray_server start
	echo "All Install Done!"
	echo "#########################################################################"
}

Do_Uninstall(){
	echo "#########################################################################"
	echo "Start Uninstall xray_server..."
	service xray_server stop
	Remove_from_Crontab
	Remove_Service
	Remove_Json
	Uninstall_Bin
	echo "All Uninstall Done!"
	echo "#########################################################################"
}

Do_Re_InstallService(){
	echo "#########################################################################"
	echo "Start Re-Install xray_server Service..."
	service xray_server stop
	Remove_Service
	Create_Service
	service xray_server start
	echo "Re-Install Service Done!"
	echo "#########################################################################"
}

case "$1" in
install)			Do_Install
					;;
uninstall)			Do_Uninstall
					;;
optimizeparameters)	Optimize_Parameters
					;;
reinstallservice)	Do_Re_InstallService
					;;
rngtools)			Install_Rng_tools
					;;
bbr)				Install_BBR
					;;
*)					echo "Usage: install|uninstall|optimizeparameters|reinstallservice|rngtools|bbr"
					exit 2
					;;
esac
exit 0
