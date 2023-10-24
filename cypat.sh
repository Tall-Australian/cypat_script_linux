#!/bin/bash

# Create backups
echo "Creating backups..."
cat /etc/pam.d/common-password > /etc/pam.d/common-password.bak
cat /etc/ftpusers > /etc/ftpusers.bak
cat /etc/ssh/sshd_config > /etc/ssh/sshd_config.bak
cat /etc/selinux/config > /etc/selinux/config.bak
cat /etc/login.defs > /etc/login.defs.bak
cat /etc/sysctl.conf > /etc/sysctl.conf.bak

# Config PAM
echo "Configuring PAM..."

echo "Configuring common-password..."
touch /etc/security/opasswd
source /etc/os-release

apt-get install libpam-pwquality -y
echo "password required pam_pwquality.so" > /etc/pam.d/common-password
echo "password [success=1 default=ignore] pam_unix.so yescrypt remember=5 use_authok shadow" >> /etc/pam.d/common-password
echo "password requisite pam_deny.so" >> /etc/pam.d/common-password
echo "password required pam_permit.so" >> /etc/pam.d/common-password
echo "password optional pam_gnome_keyring.so" >> /etc/pam.d/common-password
echo "difok=4" > /etc/security/pwquality.conf
echo "minlen=12" >> /etc/security/pwquality.conf
echo "minclass=4" >> /etc/security/pwquality.conf
echo "retry=5" >> /etc/security/pwquality.conf

sed -i "s/^PASS_MIN_DAYS/PASS_MIN_DAYS 12; s/^PASS_MAX_DAYS/PASS_MAX_DAYS 90" /etc/login.defs

echo "Configuring common-auth..."
# TODO: rest of pam

rm -f /etc/ftpusers

# ufw
echo "Installing and configuring ufw..."
apt-get install ufw -y
ufw disable
ufw default deny incoming
ufw default allow outgoing
ufw deny telnet # Deny insecure protocols
ufw deny tftp
ufw deny rdp
ufw deny vnc
ufw deny 512
ufw deny 513
ufw deny 514
ufw deny rsh
ufw deny ldap
ufw deny 50000 # Deny C2 servers
ufw deny 55553
ufw allow out https
ufw limit ssh
ufw enable

# Arg parsing and user adding time
echo "Manging users and applications..."
while getopts ":n:l:d:i:u:s:g:o:" o; do
    case "${o}" in
        n)
            n=${OPTARG}
            IFS=':' read -a arr <<< "$line"
            useradd -m -U ${arr[0]}
        l)
            l=${OPTARG}
            passwd -l ${l}
            ;;
        d)
            d=${OPTARG}
            userdel ${OPTARG} # Keep home directory just in case
            ;;
        
        i)
            i=${OPTARG}
            apt-get install ${i} -y
            ;;
        u)
            u=${OPTARG}
            apt-get remove ${d} -y
            ;;
        s)
            # SELinux
            apt-get install selinux-basics selinux-policy-default auditd -y
            selinux-activate
            echo "SELINUX=enforcing" > /etc/selinux/config
            echo "SELINUXTYPE=strict" >> /etc/selinux/config
            echo "SELinux has been enabled."
            ;;
        g)
            IFS=':' read -a arr <<< "$line"
            usermod -aG ${arr[1]} ${arr[0]}
            ;;
        o)
            ufw disable
            ufw default deny outgoing
            ufw allow ssh
            ufw allow https
            ufw allow dns
            echo "Default deny outgoing enabled."
    esac
done

users=($(getent passwd | awk -F: '($3>=1000)&&($3<60000){print $1}'))
me=$(who ran sudo | awk '{print $1}')

if ! type mkpasswd &>/dev/null
then
      apt-get install whois
fi

for value in $users; do
      lchage -m 12 -M 90 -W 7 $value
      
      if [ "$value" != "$me" ]
      then
            mkpasswd -l 16 $value > /dev/null
      fi
done

# Malware protection
echo "Installing and running malware protection..."

echo "Handling rkhunter..."
apt-get install rkhunter -y && rkhunter --propupd && rkhunter -c --skip-keypress

echo "Configuring and running clamav..."
apt-get install clamav clamav-daemon -y
mkdir /var/log/clamav
mkdir /root/quarantine
touch /var/log/clamav/clamdscan.log
freshclam
systemctl start clamav-freshclam
systemctl enable clamav-daemon
systemctl start clamav-daemon
sed -i -e '/^#?LogFile=/!p;$aLogFile=/var/log/clamav/clamdscan.log;/^#?LogTime=/!p;$aLogTime=yes;/^#?LogVerbose=/!p;$aLogVerbose=yes;/^#?DetectBrokenExecutables=/!p;$DetectBrokenExecutables=yes;' /etc/clamav/clamd.conf
printf "ExcludePath ^/proc\nExcludePath ^/sys\nExcludePath ^/run\nExcludePath ^/dev\nExcludePath ^/snap\nExcludePath ^/var/lib/lxcfs/cgroup\nExcludePath ^/root/quarantine\n" >> /etc/clamav/clamd.conf 
echo "0 0 * * 0 root /usr/bin/clamdscan -m --fdpass --move=/root/quarantine /" >> /etc/cron.d/clamdscan
systemctl restart clamav-daemon
clamdscan -m --remove --fdpass /

echo "Handling common applications..."
systemctl stop nginx -y
apt purge wireshark dwarf-fortress tor nmap ophcrack telnet telnetd crack hashcat hashcat-legacy john rainbowcrack npcap netcat -y

apt autoremove -y

# Write new sshd_config
echo "Configuring ssh..."

# I know not how this works, ChatGPT wrote it for me.
sed -i -e 's/^#?LogLevel .*/LogLevel VERBOSE/; s/^#?Ciphers .*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/; s/^#?HostKeyAlgorithms .*/HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss/; s/^#?KexAlgorithms .*/KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha25/; s/^#?MACs .*/MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1/; s/^#?PermitRootLogin .*/PermitRootLogin no/; s/^#?UsePAM .*/UsePAM yes/; s/^#?AllowTcpForwarding .*/AllowTcpForwarding no/; s/^#?AllowStreamLocalForwarding .*/AllowStreamLocalForwarding no/; s/^#?GatewayPorts .*/GatewayPorts no/; s/^#?PermitTunnel .*/PermitTunnel no/; s/^#?X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config

echo "Configuring the kernel..."

echo "Configuring /etc/sysctl.conf..."
echo "net.ipv4.ip_forward = 0" > /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "kernel.sysrq = 0" >> /etc/sysctl.conf
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 5" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.router_solicitations = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.autoconf = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.dad_transmits = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.max_addresses = 1" >> /etc/sysctl.conf
echo "kernel.exec-shield = 2" >> /etc/sysctl.conf
echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
echo "fs.file-max = 65535" >> /etc/sysctl.conf
echo "kernel.pid_max = 65536" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_port_range = 2000 65000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf
echo "kernel.panic=10" >> /etc/sysctl.conf
echo "fs.protected_hardlinks=1" >> /etc/sysctl.conf
echo "fs.protected_symlinks=1" >> /etc/sysctl.conf

echo "Disabling USBs..."
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

# TODO: mas

echo "Updating and restaring..."
apt-get update -y && apt-get upgrade -y
read -p "About to reboot, press enter to continue..." dummy
reboot
