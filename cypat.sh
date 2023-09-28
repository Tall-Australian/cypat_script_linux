#!/bin/bash

# Create backups
echo "Creating backups..."
cat /etc/pam.d/common-password > /etc/pam.d/common-password.bak
cat /etc/ftpusers > /etc/ftpusers.bak
cat /etc/ssh/sshd_config > /etc/ssh/sshd_config.bak
cat /etc/selinux/config > /etc/selinux/config.bak

# Config passwords
echo "Configuring PAM and updating password policy..."
apt-get install libpam-cracklib -y
apt-get install libpam-pwquality -yt
touch /etc/security/opasswd
echo "password required pam_cracklib.so retry=3 minlen=12 difok=4" > /etc/pam.d/common-password
echo "password sufficient pam_unix.so sha512 remember=5 use_authok shadow" >> /etc/pam.d/common-password
echo "password required pam_deny.so" >> /etc/pam.d/common-password

users=$(awk -F: '{ print $1}' /etc/passwd)

for value in $users
do
      chage -m 12 -M 90 -W 7 $value
done
# TODO: rest of pam

rm -f /etc/ftpusers

# ufw
echo "Installing and configuring ufw..."
apt-get install ufw -y
ufw disable
ufw deny telnet
ufw allow ssh # TODO: More detail on protocols
ufw enable

chpassd_list=()
empty=()

# Arg parsing and user adding time
echo "Manging users and applications..."
while getopts ":n:p:" o; do
    case "${o}" in
        n)
            n=${OPTARG}
            IFS=':' read -a arr <<< "$line"
            useradd -m -U ${arr[0]}
            echo ${arr[1]} | passwd --stdin ${arr[0]}
            ;;
        l)
            l=${OPTARG}
            passwd -l ${l}
            ;;
        d)
            d=${OPTARG}
            userdel ${OPTARG} # Keep home directory just in case
            ;;
        c)
            c=${OPTARG}
            chpassd_list+=(${c})
            ;;
        i)
            i=${OPTARG}
            apt-get install ${i} -y
            ;;
        u)
            u=${OPTARG}
            apt-get install ${d} -y
            ;;
        s)
            # SELinux
            apt-get install selinux-basics selinux-policy-default auditd -y
            selinux-activate
            echo "SELINUX=enforcing" > /etc/selinux/config
            echo "SELINUXTYPE=strict" >> /etc/selinux/config
            echo "SELinux has been enabled."
            ;;
    esac
done

if [ ! "$chpassd_list" ==  "$empty" ]; then
      for line in $chpassd_list; do
          echo "$line"
      done | chpassd
fi

# Malware protection
echo "Installing and running malware protection..."
apt-get install rkhunter -y && rkhunter --propupd && rkhunter -c --skip-keypress
apt-get install clamav clamav-daemon -y &&
freshclam &&
systemctl start clamav-freshclam &&
clamscan -i -r --remove /

# Write new sshd_config
echo "Configuring ssh..."
echo "LogLevel VERBOSE" > /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss" >> /etc/ssh/sshd_config
echo "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha25" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "UsePAM yes" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "AllowStreamLocalForwarding no" >> /etc/ssh/sshd_config
echo "GatewayPorts no" >> /etc/ssh/sshd_config
echo "PermitTunnel no" >> /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
echo "MaxAuthTries 5" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

# TODO: mas

echo "Updating and restaring..."
apt-get update -y && apt-get upgrade -y
read -p "About to reboot, press enter to continue..." dummy
reboot
