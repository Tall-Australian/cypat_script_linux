#!/bin/bash

# Create backups
echo "Creating backups..."
cat /etc/pam.d/common-password > /etc/pam.d/common-password.bak
cat /etc/ftpusers > /etc/ftpusers.bak
cat /etc/ssh/sshd_config > /etc/ssh/sshd_config.bak
cat /etc/selinux/config > /etc/selinux/config.bak

# Config PAM
echo "Configuring PAM..."

echo "Configuring common-password..."
touch /etc/security/opasswd
source /etc/os-release

if [ "$ID" == "debian" ]; then
      apt-get install libpam-cracklib -y
      echo "#%PAM-1.0" > /etc/pam.d/common-password
      echo "password required pam_cracklib.so retry=3 minlen=12 difok=4 minclass=4" >> /etc/pam.d/common-password
      echo "password [success=1 default=ignore] pam_unix.so yescrypt remember=5 use_authok shadow" >> /etc/pam.d/common-password
      echo "password requisite pam_deny.so" >> /etc/pam.d/common-password
      echo "password required pam_permit.so" >> /etc/pam.d/common-password
      echo "password optional pam_gnome_keyring.so" >> /etc/pam.d/common-password
else
      echo "difok=4" > /etc/security/pwquality.conf
      echo "minlen=12" >> /etc/security/pwquality.conf
      echo "minclass=4" >> /etc/security/pwquality.conf
fi

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

chpassd_list=()
empty=()

# Arg parsing and user adding time
echo "Manging users and applications..."
while getopts ":n:l:d:c:i:u:s:g:" o; do
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
        g)
            IFS=':' read -a arr <<< "$line"
            usermod -aG ${arr[1]} ${arr[0]}
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
# I know not how this works, ChatGPT wrote it for me.
sed -i -E 's/^#?LogLevel .*/LogLevel VERBOSE/; s/^#?Ciphers .*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/; s/^#?HostKeyAlgorithms .*/HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss/; s/^#?KexAlgorithms .*/KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha25/; s/^#?MACs .*/MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1/; s/^#?PermitRootLogin .*/PermitRootLogin no/; s/^#?UsePAM .*/UsePAM yes/; s/^#?AllowTcpForwarding .*/AllowTcpForwarding no/; s/^#?AllowStreamLocalForwarding .*/AllowStreamLocalForwarding no/; s/^#?GatewayPorts .*/GatewayPorts no/; s/^#?PermitTunnel .*/PermitTunnel no/; s/^#?X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config

# TODO: mas

echo "Updating and restaring..."
apt-get update -y && apt-get upgrade -y
read -p "About to reboot, press enter to continue..." dummy
reboot
