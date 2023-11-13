#!/bin/bash
#
# ==================================================
# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(curl -sS ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

#detail nama perusahaan
country=ID
state=Indonesia
locality=Jakarta
organization=none
organizationalunit=none
commonname=none
email=none

# simple password minimal
curl -sS https://raw.githubusercontent.com/SARTAMP/src/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

#install python
apt install python -y

#install jq
apt -y install jq

#install shc
apt -y install shc

# install wget and curl
apt -y install wget curl

#figlet
apt-get install figlet -y
apt-get install ruby -y
gem install lolcat

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

install_ssl(){
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            else
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            fi
    else
        yum install -y nginx certbot
        sleep 3s
    fi

    systemctl stop nginx.service

    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            else
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            fi
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
        sleep 3s
    fi
}

# install webserver
apt -y install nginx
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/nginx.conf"
mkdir -p /home/vps/public_html
/etc/init.d/nginx restart

# install badvpn
cd
wget -O /usr/sbin/badvpn "https://raw.githubusercontent.com/casper9/script/main/badvpn" >/dev/null 2>&1
chmod +x /usr/sbin/badvpn > /dev/null 2>&1
wget -q -O /etc/systemd/system/badvpn1.service "https://raw.githubusercontent.com/casper9/script/main/badvpn1.service" >/dev/null 2>&1
wget -q -O /etc/systemd/system/badvpn2.service "https://raw.githubusercontent.com/casper9/script/main/badvpn2.service" >/dev/null 2>&1
wget -q -O /etc/systemd/system/badvpn3.service "https://raw.githubusercontent.com/casper9/script/main/badvpn3.service" >/dev/null 2>&1
systemctl disable badvpn1 
systemctl stop badvpn1 
systemctl enable badvpn1
systemctl start badvpn1 
systemctl disable badvpn2 
systemctl stop badvpn2 
systemctl enable badvpn2
systemctl start badvpn2 
systemctl disable badvpn3 
systemctl stop badvpn3 
systemctl enable badvpn3
systemctl start badvpn3 

# setting port ssh
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 53' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

cd
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/#DROPBEAR_EXTRA_ARGS=/g' /etc/default/dropbear
sed -i '/arguments for Dropbear/a DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

# install stunnel
cd
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 8880
connect = 127.0.0.1:22

[dropbear]
accept = 8443
connect = 127.0.0.1:109

[ws-stunnel]
accept = 444
connect = 700

[openvpn]
accept = 990
connect = 127.0.0.1:1194

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

#OpenVPN
cd
wget https://raw.githubusercontent.com/casper9/script/main/vpn.sh &&  chmod +x vpn.sh && ./vpn.sh

#slowdns
cd
wget https://raw.githubusercontent.com/casper9/script/main/installsl.sh && chmod +x installsl.sh && ./installsl.sh

#udpcostum
cd
wget https://raw.githubusercontent.com/SARTAMP/src/main/udp/udp-custom.sh && chmod +x udp-custom.sh && ./udp-custom.sh

# // install lolcat
wget https://raw.githubusercontent.com/casper9/script/main/lolcat.sh &&  chmod +x lolcat.sh && ./lolcat.sh

# memory swap 10gb
cd
dd if=/dev/zero of=/swapfile bs=1024 count=5242880
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# banner /etc/issue.net
echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

# Ganti Banner
wget -O /etc/issue.net "https://raw.githubusercontent.com/casper9/script/main/issue.net"

#install bbr dan optimasi kernel
wget https://raw.githubusercontent.com/SARTAMP/src/main/ssh/bbr.sh && chmod +x bbr.sh && ./bbr.sh

# blokir torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# download script
cd /usr/bin
wget -q -O usernew "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/usernew.sh"
wget -q -O hapus "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/hapus.sh"
wget -q -O member "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/member.sh"
wget -q -O renew "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/renew.sh"
wget -q -O cek "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/cek.sh"
wget -q -O add-host "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/add-host.sh"
wget -q -O speedtest "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/speedtest_cli.py"
wget -q -O xp "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/xp.sh"
wget -q -O asu "https://raw.githubusercontent.com/SARTAMP/src/main/asu.sh"
wget -q -O menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/menu.sh"
wget -q -O sshws "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/sshws.sh"
wget -q -O trial "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/trial.sh"
wget -q -O ssh-menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/ssh-menu.sh"
wget -q -O v2ray-menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/v2ray-menu.sh"
wget -q -O trojan-menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/trojan-menu.sh"
wget -q -O ssgrpc-menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/ssgrpc-menu.sh"
wget -q -O cekws "https://raw.githubusercontent.com/SARTAMP/src/main/xray/cekws.sh"
wget -q -O about "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/about.sh" 
wget -q -O running "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/running.sh"
wget -q -O banner "https://raw.githubusercontent.com/SARTAMP/src/main/banner.sh"
wget -q -O del-tr "https://raw.githubusercontent.com/SARTAMP/src/main/xray/del-tr.sh"
wget -q -O trial-menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/trial-menu.sh"
wget -q -O info-menu "https://raw.githubusercontent.com/SARTAMP/src/main/menu_all/info-menu.sh"
wget -q -O ceklim "https://raw.githubusercontent.com/SARTAMP/src/main/ssh/ceklim.sh"
wget -q -O cekusage "https://raw.githubusercontent.com/SARTAMP/src/main/xray/cekusage.sh"
wget -q -O cekxray "https://raw.githubusercontent.com/SARTAMP/src/main/cekxray.sh"
chmod +x usernew
chmod +x menu
chmod +x hapus
chmod +x member
chmod +x renew
chmod +x cek
chmod +x add-host
chmod +x speedtest
chmod +x xp
chmod +x asu
chmod +x sshws
chmod +x trial
chmod +x ssh-menu
chmod +x v2ray-menu
chmod +x trojan-menu
chmod +x ssgrpc-menu
chmod +x cekws
chmod +x about
chmod +x running
chmod +x banner
chmod +x del-tr
chmod +x trial-menu
chmod +x info-menu
chmod +x ceklim
chmod +x cekusage
chmod +x cekxray
cd

cat > /etc/cron.d/re_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /sbin/reboot
END

cat > /etc/cron.d/clean_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * root /sbin/logcleaner
END

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-END
0
END

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1
service cron start >/dev/null 2>&1

# remove unnecessary files
sleep 1
echo -e "[ ${green}INFO$NC ] Clearing trash"
apt autoclean -y >/dev/null 2>&1

if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi

cd
chown -R www-data:www-data /home/vps/public_html
sleep 0.5
echo -e "$yell[SERVICE]$NC Restart All service SSH & OVPN"
/etc/init.d/nginx restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting nginx"
/etc/init.d/openvpn restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting cron "
/etc/init.d/ssh restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting ssh "
/etc/init.d/dropbear restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting dropbear "
/etc/init.d/fail2ban restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting fail2ban "
/etc/init.d/stunnel4 restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting stunnel4 "
/etc/init.d/vnstat restart >/dev/null 2>&1
sleep 0.5
echo -e "[ ${green}ok${NC} ] Restarting vnstat "
/etc/init.d/squid restart >/dev/null 2>&1
history -c
echo "unset HISTFILE" >> /etc/profile

rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh
rm -rf /etc/apache2

clear
