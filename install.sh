#!/bin/bash

INST_PATH=/opt/ffbackup
CONFIG_PATH=/etc/ffbackup

set -e

if [ $UID -ne 0 ]; then
    echo 'fatal error: must be run as root!'
    exit 1
fi

cd `dirname "$0"`
echo 'copying files...'
mkdir -p "$INST_PATH"
mkdir -p "$CONFIG_PATH"
cp -v -f -t "$INST_PATH" ffbackup-client ffbackup-restore ffbackup-restore-gui
cp -v -n -t "$CONFIG_PATH" client.cfg

echo
echo 'creating user ffbackup'
id -u ffbackup >/dev/null 2>&1 || useradd -c 'FFBackup System' -d /nonexistent -M -s /bin/false ffbackup

echo
echo 'installation finished'
