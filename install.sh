#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

SS_PORT=58388
SSH_PORT=62222
SS_METHOD=chacha20-ietf-poly1305

apt update  -y
apt upgrade -y
apt install -y shadowsocks-libev qrencode
apt install -y build-essential python3-dev libnetfilter-queue-dev
apt install -y python3-pip
pip install NetfilterQueue
pip install scapy

# HOME_DIR=`eval echo ~$SUDO_USER`
HOME_DIR=$HOME
DEF_IFACE=`ip r | grep default | head -1 |  cut -f 5 -d ' '`
MYIP=`ip a show dev $DEF_IFACE | grep -Eo 'inet.*brd' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'`
PASSWD_LEN=12
SS_PASSWD=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "$PASSWD_LEN" | head -n 1)
URI=`echo -n "$SS_METHOD:$SS_PASSWD@$MYIP:$SS_PORT" | base64 | tr -d '='`
URI=ss://$URI
echo $URI > $HOME_DIR/ss.uri

#####################
# Shadowsocks setup #
#####################

# server config
cat > /etc/shadowsocks-libev/config.json << eof
{
    "server":["0.0.0.0"],
    "mode":"tcp_and_udp",
    "server_port":$SS_PORT,
    "local_port":1080,
    "password":"$SS_PASSWD",
    "timeout":60,
    "method":"$SS_METHOD"
}
eof

# Client config
cat > $HOME_DIR/client.json << eof
{
    "server":"$MYIP",
    "mode":"tcp_and_udp",
    "server_port":$SS_PORT,
    "local_port":1080,
    "password":"$SS_PASSWD",
    "timeout":60,
    "method":"$SS_METHOD"
}
eof

systemctl daemon-reload
systemctl enable --now shadowsocks-libev.service
systemctl restart shadowsocks-libev.service



###################
# Fingerprint fix #
###################

mkdir -p ${HOME}/tcp2win
cat > ${HOME}/tcp2win/tcp2win.py << eof
#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import *
def print_and_accept(PKT):
    data = PKT.get_payload()
    pkt = IP(data)
    opt = pkt[TCP].options
    if len(opt) == 6:
        pkt[TCP].options = [opt[0], opt[1], opt[5], opt[2], opt[4], opt[3]]
        if pkt[TCP].window != 64240:
            pkt[TCP].window = 64240
            pkt[TCP].chksum = None
            pkt[IP].chksum = None
        send(pkt)
        PKT.drop()
    else:
        PKT.accept()
nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
conf.verb = 0
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')
nfqueue.unbind()
eof

chmod +x ${HOME}/tcp2win/tcp2win.py

cat > /etc/systemd/system/tcp2win.service << eof
[Unit]
Description=TCP fingerprint fix
After=network.target
Wants=network.target

[Service]
User=root
Type=simple
ExecStartPre=iptables -I OUTPUT -o $DEF_IFACE --protocol tcp --tcp-flags ALL SYN -j NFQUEUE --queue-num 1
ExecStart=${HOME}/tcp2win/tcp2win.py
ExecStopPost=iptables -D OUTPUT -o $DEF_IFACE --protocol tcp --tcp-flags ALL SYN -j NFQUEUE --queue-num 1
Restart=always

[Install]
WantedBy=multi-user.target
eof

systemctl daemon-reload
systemctl enable --now tcp2win.service
systemctl restart tcp2win.service

echo "net.ipv4.tcp_window_scaling=1"         >> /etc/sysctl.conf
echo "net.ipv4.ip_default_ttl=128"           >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps=0"             >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 130000 8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 141000 8388608" >> /etc/sysctl.conf

echo 1   > /proc/sys/net/ipv4/tcp_window_scaling
echo 128 > /proc/sys/net/ipv4/ip_default_ttl
echo 0   > /proc/sys/net/ipv4/tcp_timestamps
echo "4096 130000 8388608" > /proc/sys/net/ipv4/tcp_rmem
echo "4096 141000 8388608" > /proc/sys/net/ipv4/tcp_wmem


##################
# Firewall setup #
##################

ufw disable

# disable ipv6
# echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 
# echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 
# echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6
# echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
# echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
# echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

apt install -y iptables-persistent

# Change ssh port
sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
systemctl restart sshd.service

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,ACK -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport $SSH_PORT -j ACCEPT
iptables -A INPUT -p udp -m udp --dport $SS_PORT -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport $SS_PORT -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP

iptables-save > /etc/iptables/rules.v4

echo 
echo '**************************************************'
echo '* TCP fingerprint was installed successfully!    *'
echo '**************************************************'
echo '*                                                *'
echo '**************************************************'
echo '* Firewall sepup completed successfully!         *'
echo '*                                                *'
echo "* Your new ssh port: $SSH_PORT                       *"
echo '**************************************************'
echo '*                                                *'
echo '**************************************************'
echo '* Shadowsocks server was installed successfully! *'
echo '*                                                *'
echo '* see your client configs below.                 *'
echo '**************************************************'
echo 
cat $HOME_DIR/client.json
echo
cat $HOME_DIR/ss.uri
