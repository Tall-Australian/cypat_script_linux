#!/bin/bash

# Config passwords
apt-get install libpam-cracklib -y
apt-get install libpam-pwquality -y

passwd -n 12 -x 90

# TODO: rest of pam
awk -F : '{if ($3<1000) print $1}' /etc/passwd > /etc/ftpusers

# ufw
apt-get install ufw -y
ufw disable
ufw deny telnet
ufw allow ssh # TODO: More detail on protocols
ufw enable

# TODO: mas

apt-get update -y && apt-get upgrade -y
