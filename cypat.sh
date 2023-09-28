#!/bin/bash

# Config passwords
apt-get install libpam-cracklib -y
apt-get install libpam-pwquality -yt
touch /etc/security/opasswd
echo "password required pam_cracklib.so retry=3 minlen=12 difok=4" > /etc/pam.d/common-password
echo "password required pam_unix.so sha512 remember=5 use_authok" >> /etc/pam.d/common-password
#!/bin/bash
users=$(awk -F: '{ print $1}' /etc/passwd)

for value in $users
do
      chage -m 12 -M 90 -W 7 $value
done

# TODO: rest of pam
awk -F : '{if ($3<1000) print $1}' /etc/passwd > /etc/ftpusers

# ufw
apt-get install ufw -y
ufw disable
ufw deny telnet
ufw allow ssh # TODO: More detail on protocols
ufw enable

chpassd_list=()
empty=()

# Arg parsing and user adding time
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
        c)
            c=${OPTARG}
            chpassd_list+=(${c})
            ;;
    esac
done

if [ ! "$chpassd_list" ==  "$empty" ]; then
      for line in $chpassd_list; do
          echo "$line"
      done | chpassd
fi

# TODO: mas

apt-get update -y && apt-get upgrade -y
