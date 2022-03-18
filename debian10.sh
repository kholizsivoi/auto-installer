#!/bin/bash
##################
# Script name
MyScriptName='Sivoi'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='143'

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/kholizsivoi/script/master/issue.net'

# Dropbear Ports
Dropbear_Port1='80'
Dropbear_Port2='442'

# Stunnel Ports
Stunnel_Port1='443' # through Dropbear
Stunnel_Port2='444' # through OpenSSH

# OpenVPN Ports
OpenVPN_TCP_Port='1194'
OpenVPN_UDP_Port='25000'

# Privoxy Ports
Privoxy_Port1='3129'
Privoxy_Port2='8081'

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8080'

# OpenVPN Config Download Port
OvpnDownload_Port='81' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Jakarta'

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y

 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 
 # Now installing all our wanted services
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq fail2ban -y

 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
 apt-get update
 apt-get install openvpn -y
}

function InstWebmin(){
 # Download the webmin .deb package
 # You may change its webmin version depends on the link you've loaded in this variable(.deb file only, do not load .zip or .tar.gz file):
 WebminFile='https://raw.githubusercontent.com/kholizsivoi/script/master/webmin_1.920_all.deb'
 wget -qO webmin.deb "$WebminFile"
 
 # Installing .deb package for webmin
 dpkg --install webmin.deb
 
 rm -rf webmin.deb
 
 # Configuring webmin server config to use only http instead of https
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 
 # Then restart to take effect
 systemctl restart webmin
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/issue.net
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/issue.net
 wget -qO /etc/issue.net "$SSH_Banner"
 dos2unix -q /etc/issue.net

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/issue.net"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=ID/ST=Jawa Timur/L=Lamongan/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:80

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:22
MyStunnelC

 # setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir

}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf' > /etc/openvpn/server_tcp.conf
# OpenVPN TCP
port OVPNTCP
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.200.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log tcp.log
verb 2
ncp-disable
cipher none
auth none
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port OVPNUDP
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log udp.log
verb 2
ncp-disable
cipher none
auth none
myOpenVPNconf2

 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIB1zCCAX2gAwIBAgIUHRGGBgXyGjA896h+1oPxHXpNrIEwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTY25fZzVtUUZJQXF2SzcxcjVzMjAeFw0yMjAzMTgwMzI2NTda
Fw0zMjAzMTUwMzI2NTdaMB4xHDAaBgNVBAMME2NuX2c1bVFGSUFxdks3MXI1czIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQkKNtJRYxdE3altvEgxapCLv5mRtbH
UW/2tk3Z8t66GJ4DpPwVaH456pkUxz6Xsr3DyF1wlAusq4JhatoWEzMMo4GYMIGV
MB0GA1UdDgQWBBSkQlosnKhddHbif2IOoPyq1kBqvzBZBgNVHSMEUjBQgBSkQlos
nKhddHbif2IOoPyq1kBqv6EipCAwHjEcMBoGA1UEAwwTY25fZzVtUUZJQXF2Szcx
cjVzMoIUHRGGBgXyGjA896h+1oPxHXpNrIEwDAYDVR0TBAUwAwEB/zALBgNVHQ8E
BAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgeAd244o1o1v0hZ22wsR2Ho0OtN1ygS/a
rczYq4TFkr4CIQDzpqGWaAyZNvwvrYcRbKzren6lckMhsUL+SoN92UjQNg==
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            17:7e:99:81:64:6b:75:b6:0b:19:0c:19:2a:dc:ab:97
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=cn_g5mQFIAqvK71r5s2
        Validity
            Not Before: Mar 18 03:27:23 2022 GMT
            Not After : Jun 20 03:27:23 2024 GMT
        Subject: CN=server_6GYa1Y1FegrBAFGC
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:52:ed:09:4e:67:10:61:c0:98:d3:85:a3:62:ab:
                    4a:5a:eb:82:c6:21:ec:5d:c6:7a:52:3d:4f:62:87:
                    c4:67:09:4a:42:6d:ab:61:6d:3e:3c:a5:d8:f8:75:
                    e1:01:0f:0e:8d:db:8b:46:12:71:03:d5:c3:00:07:
                    c8:f0:e9:70:9c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                C3:58:72:F5:AE:EB:B1:7D:3E:13:71:3E:5E:AE:34:08:A4:BA:A2:3B
            X509v3 Authority Key Identifier: 
                keyid:A4:42:5A:2C:9C:A8:5D:74:76:E2:7F:62:0E:A0:FC:AA:D6:40:6A:BF
                DirName:/CN=cn_g5mQFIAqvK71r5s2
                serial:1D:11:86:06:05:F2:1A:30:3C:F7:A8:7E:D6:83:F1:1D:7A:4D:AC:81

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server_6GYa1Y1FegrBAFGC
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:0e:71:01:08:9a:a4:2e:fd:33:bb:9a:b5:98:bf:
         3a:12:de:bd:94:c7:b5:ed:63:2f:73:59:7d:cd:99:59:f8:33:
         02:21:00:cc:1e:76:79:c0:0d:c2:06:03:20:94:48:35:7f:bf:
         dd:0c:59:d8:79:8c:39:70:06:2a:2f:1e:71:f0:f9:76:bb
-----BEGIN CERTIFICATE-----
MIICDTCCAbOgAwIBAgIQF36ZgWRrdbYLGQwZKtyrlzAKBggqhkjOPQQDAjAeMRww
GgYDVQQDDBNjbl9nNW1RRklBcXZLNzFyNXMyMB4XDTIyMDMxODAzMjcyM1oXDTI0
MDYyMDAzMjcyM1owIjEgMB4GA1UEAwwXc2VydmVyXzZHWWExWTFGZWdyQkFGR0Mw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARS7QlOZxBhwJjThaNiq0pa64LGIexd
xnpSPU9ih8RnCUpCbathbT48pdj4deEBDw6N24tGEnED1cMAB8jw6XCco4HOMIHL
MAkGA1UdEwQCMAAwHQYDVR0OBBYEFMNYcvWu67F9PhNxPl6uNAikuqI7MFkGA1Ud
IwRSMFCAFKRCWiycqF10duJ/Yg6g/KrWQGq/oSKkIDAeMRwwGgYDVQQDDBNjbl9n
NW1RRklBcXZLNzFyNXMyghQdEYYGBfIaMDz3qH7Wg/Edek2sgTATBgNVHSUEDDAK
BggrBgEFBQcDATALBgNVHQ8EBAMCBaAwIgYDVR0RBBswGYIXc2VydmVyXzZHWWEx
WTFGZWdyQkFGR0MwCgYIKoZIzj0EAwIDSAAwRQIgDnEBCJqkLv0zu5q1mL86Et69
lMe17WMvc1l9zZlZ+DMCIQDMHnZ5wA3CBgMglEg1f7/dDFnYeYw5cAYqLx5x8Pl2
uw==
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgE5ws8Qp5QskKVp0Z
HrxbojndtlUQFwvmKQZYh8pIzryhRANCAARS7QlOZxBhwJjThaNiq0pa64LGIexd
xnpSPU9ih8RnCUpCbathbT48pdj4deEBDw6N24tGEnED1cMAB8jw6XCc
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAqlPbJcdTOT2hP9LAOE6BRZ563PI1y5j+SxFOQJ3pKn2Vv8qNjqap
TPQixazUv86zxJyqx0QCY2H8gFM4PFhmbuMMCQtAJ5dof1fmvzLXib2+ux0ndxTs
MgaEyXOXVsUMDk1qHCvpBy+2LzqCvsjYnx5Xr/xSvqCrIe9hEjU5I40RBbhozYMm
1BjHOlWq3112e/Ks5KYh1jvHQoMwOpu56Zhn4UziuxVv6yUGNCH2mdZ/X4V1uG6/
UzZ0LWQ29HuvUjjtcmc5ltuFeSGvV99yGxYPopyxb4r+dfGoYILVQLcQabU00ust
hNqzmmgh+LMYi1/KNU32mME+arB8BmKqWwIBAg==
-----END DH PARAMETERS-----
EOF13

 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
done

 # Creating a New update message in server.conf
 cat <<'NUovpn' > /etc/openvpn/server.conf
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
 # 
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
 # Enjoy the new update
 # Script Updated by sivoi
NUovpn

 # setting openvpn server port
 sed -i "s|OVPNTCP|$OpenVPN_TCP_Port|g" /etc/openvpn/server_tcp.conf
 sed -i "s|OVPNUDP|$OpenVPN_UDP_Port|g" /etc/openvpn/server_udp.conf
 
 # Getting some OpenVPN plugins for unix authentication
 cd
 wget https://raw.githubusercontent.com/kholizsivoi/script/master/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
 sysctl --system &> /dev/null

 # Iptables Rule for OpenVPN server
 cat <<'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
 chmod +x /etc/openvpn/openvpn.bash
 bash /etc/openvpn/openvpn.bash

 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl enable openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_udp

}
function InsProxy(){

 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # Removing Duplicate Squid config
 rm -rf /etc/squid/squid.con*
 
 # Creating Squid server config using cat eof tricks
 cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:Squid_Port1
http_port 0.0.0.0:Squid_Port2
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname sivoi
mySquid

 # Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf
 
 # Setting squid ports
 sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf
 sed -i "s|Squid_Port2|$Squid_Port2|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server..."
 systemctl restart squid
}

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/sivoi-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/sivoi-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 
cat <<EOF162> /var/www/openvpn/client-udp.ovpn
client
dev tun
proto udp
remote $IPADDR $OpenVPN_UDP_Port
remote-cert-tls server
resolv-retry infinite
float
fast-io
nobind
tun-mtu 1500
mssfix 1460
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
redirect-gateway def1
setenv CLIENT_CERT 0
reneg-sec 0
verb 3

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF162

cat <<EOF1152> /var/www/openvpn/client-tcp.ovpn
client
dev tun
proto tcp-client
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 3
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF1152

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site by sivoi-->

<head><meta charset="utf-8" /><title>sivoi OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> UDP Server For TU/CTC/CTU Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/sun-tuudp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> TCP+Proxy Server For TU/CTC/CTU Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/sun-tuudp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Globe/TM <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For EasySURF/GoSURF/GoSAKTO Promos with WNP,SNS,FB and IG freebies</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/gtmwnp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Modem</span><br /><small> Without Promo/Noload (Reconnecting Server, Use Low-latency VPS for fast reconnectivity)</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/sun-noload.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r tcpudp.zip *.ovpn
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job

 # Creating directory for startup script
 rm -rf /etc/sivoi
 mkdir -p /etc/sivoi
 chmod -R 755 /etc/sivoi
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/sivoi/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
exit 0
EOFSH
 chmod +x /etc/sivoi/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/sivoi/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 cat <<'FordServ' > /etc/systemd/system/sivoi.service
[Unit]
Description=sivoi
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/sivoi/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FordServ
 chmod +x /etc/systemd/system/sivoi.service
 systemctl daemon-reload
 systemctl start sivoi
 systemctl enable sivoi &> /dev/null
 systemctl enable fail2ban &> /dev/null
 systemctl start fail2ban &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}


function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}

wget -O menu "https://raw.githubusercontent.com/kholizsivoi/script/master/menu.sh"
	wget -O user-add "https://raw.githubusercontent.com/kholizsivoi/script/master/user-add.sh"
	wget -O trial "https://raw.githubusercontent.com/kholizsivoi/script/master/trial.sh"
	wget -O user-del "https://raw.githubusercontent.com/kholizsivoi/script/master/hapus.sh"
	wget -O user-login "https://raw.githubusercontent.com/kholizsivoi/script/master/user-login.sh"
	wget -O user-list "https://raw.githubusercontent.com/kholizsivoi/script/master/user-list.sh"
	wget -O expdel "https://raw.githubusercontent.com/kholizsivoi/script/master/delexp.sh"
	wget -O resvis "https://raw.githubusercontent.com/kholizsivoi/script/master/resvis.sh"
	wget -O speedtest "https://raw.githubusercontent.com/kholizsivoi/script/master/speedtest_cli.py"
	wget -O info "https://raw.githubusercontent.com/kholizsivoi/script/master/info.sh"
	wget -O about "https://raw.githubusercontent.com/kholizsivoi/script/master/about.sh"
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~
}

function ScriptMessage(){
 echo -e " $MyScriptName VPS Installer"
 echo -e ""
 echo -e ""
 echo -e ""
}

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 
 # Configure Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~
 
  # Running screenfetch
 wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/kholizsivoi/script/master/screenfetch"
 chmod +x /usr/bin/screenfetch
 echo "/bin/bash /etc/openvpn/openvpn.bash" >> .profile
 echo "clear" >> .profile
 echo "screenfetch" >> .profile

 # info
	echo "~sivoi~"
	echo "Autoscript Include:" | tee log-install.txt
	echo "===========================================" | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Service"  | tee -a log-install.txt
	echo "-------"  | tee -a log-install.txt
	echo "OpenSSH  : 22, 143"  | tee -a log-install.txt
	echo "Dropbear : 80, 442"  | tee -a log-install.txt
	echo "SSL      : 443, 444"  | tee -a log-install.txt
	echo "Squid3   : 8080, 3128 (limit to IP SSH)"  | tee -a log-install.txt
	echo "OpenVPN  : TCP 1194, UDP 25000 (client config : http://$MYIP:81/tvpudp.zip)"  | tee -a log-install.txt
	echo "badvpn   : badvpn-udpgw port 7300"  | tee -a log-install.txt
	echo "nginx    : 81"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Script"  | tee -a log-install.txt
	echo "------"  | tee -a log-install.txt
	echo "menu         (Menampilkan daftar perintah yang tersedia)"  | tee -a log-install.txt
	echo "user-add     (Membuat Akaun SSH)"  | tee -a log-install.txt
	echo "trial        (Membuat Akaun Trial)"  | tee -a log-install.txt
	echo "user-del     (Menghapus Akaun SSH)"  | tee -a log-install.txt
	echo "user-login   (Cek User Login)"  | tee -a log-install.txt
	echo "user-list    (Cek Member SSH)"  | tee -a log-install.txt
	echo "expdel       (Delete User expired)"  | tee -a log-install.txt
	echo "resvis       (Restart Service Dropbear, Webmin, Squid3, OpenVPN dan SSH)"  | tee -a log-install.txt
	echo "reboot       (Reboot VPS)"  | tee -a log-install.txt
	echo "speedtest    (Speedtest VPS)"  | tee -a log-install.txt
	echo "info         (Menampilkan Informasi Sistem)"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Fitur lain"  | tee -a log-install.txt
	echo "----------"  | tee -a log-install.txt
	echo "Webmin   : http://$MYIP:10000/"  | tee -a log-install.txt
	echo "Timezone : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
	echo "IPv6     : [off]"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Thanks To"  | tee -a log-install.txt
	echo "---------"  | tee -a log-install.txt
	echo "Allah"  | tee -a log-install.txt
	echo "Admin And All Member KPN Family"  | tee -a log-install.txt
	echo "Google"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Goup"  | tee -a log-install.txt
	echo "----"  | tee -a log-install.txt
	echo "CPM/OOCPM"  | tee -a log-install.txt
	echo "KPN IMO"  | tee -a log-install.txt
	echo "K.A.G"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "VPS AUTO REBOOT SETIAP JAM 00.00 WIB"  | tee -a log-install.txt
	echo "Log Installation --> /root/log-install.txt"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "==========================================="  | tee -a log-install.txt
	cd


echo " Please Reboot your VPS"

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog

rm -f debian10.sh
cd
