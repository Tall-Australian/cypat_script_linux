#!/bin/bash

# Create backups
echo "Creating backups..."
cat /etc/pam.d/common-password > /etc/pam.d/common-password.bak
cat /etc/ftpusers > /etc/ftpusers.bak
cat /etc/ssh/sshd_config > /etc/ssh/sshd_config.bak
cat /etc/selinux/config > /etc/selinux/config.bak
cat /etc/login.defs > /etc/login.defs.bak

# Config PAM
echo "Configuring PAM..."

echo "Configuring common-password..."
touch /etc/security/opasswd
source /etc/os-release

apt-get install libpam-pwquality -y
echo "password required pam_pwquality.so" >> /etc/pam.d/common-password
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
ufw deny telnet
ufw allow ssh # TODO: More detail on protocols
ufw enable

IFS=$'\n'; echo "${chpasswd_list[*]}" | chpasswd

# Arg parsing and user adding time
echo "Manging users and applications..."
while getopts ":n:l:d:i:u:s:g:" o; do
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
    esac
done

chpasswd_list=()
users=($(getent passwd | awk -F: '($3>=1000)&&($3<60000){print $1}'))
me=$(who ran sudo | awk '{print $1}')

if ! type pwgen &>/dev/null
then
      apt-get install pwgen
fi

for value in $users; do
      lchage -m 12 -M 90 -W 7 $value
      
      if [ "$value" != "$me" ]
      then
            password=$(pwgen -N 1 -s -y)
            chpasswd_list+=("$value:$password")
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
sed -i -e '/^#?LogFile=/!p;$aLogFile=/var/log/clamav/clamdscan.log;/^#?LogTime=/!p;$aLogTime=yes;/^#?LogVerbose=/!p;$aLogVerbose=yes;/^#?DetectBrokenExecutables=/!p;$DetectBrokenExecutables=yes;' /etc/clamav/clamd.conf
printf "ExcludePath ^/proc\nExcludePath ^/sys\nExcludePath ^/run\nExcludePath ^/dev\nExcludePath ^/snap\nExcludePath ^/var/lib/lxcfs/cgroup\nExcludePath ^/root/quarantine\n" >> /etc/clamav/clamd.conf 
echo "0 0 * * 0 root /usr/bin/clamdscan -m --fdpass --move=/root/quarantine /" >> /etc/cron.d/clamdscan

freshclam
systemctl start clamav-freshclam
systemctl enable clamav-daemon
systemctl start clamav-daemon
clamdscan -m --remove --fdpass /

echo "Handling common applications..."
systemctl stop nginx -y
apt purge wireshark dwarf-fortress tor nmap ophcrack telnet crack hashcat hashcat-legacy john rainbowcrack -y

apt autoremove -y

# Write new sshd_config
echo "Configuring ssh..."

# I know not how this works, ChatGPT wrote it for me.
sed -i -e 's/^#?LogLevel .*/LogLevel VERBOSE/; s/^#?Ciphers .*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/; s/^#?HostKeyAlgorithms .*/HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss/; s/^#?KexAlgorithms .*/KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha25/; s/^#?MACs .*/MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1/; s/^#?PermitRootLogin .*/PermitRootLogin no/; s/^#?UsePAM .*/UsePAM yes/; s/^#?AllowTcpForwarding .*/AllowTcpForwarding no/; s/^#?AllowStreamLocalForwarding .*/AllowStreamLocalForwarding no/; s/^#?GatewayPorts .*/GatewayPorts no/; s/^#?PermitTunnel .*/PermitTunnel no/; s/^#?X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config

# TODO: mas

echo "Updating and restaring..."
apt-get update -y && apt-get upgrade -y
read -p "About to reboot, press enter to continue..." dummy
reboot
