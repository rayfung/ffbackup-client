#!/bin/bash

INST_PATH=/opt/ffbackup
CONFIG_PATH=/etc/ffbackup
CRON_JOB_PATH=/etc/cron.d

set -e

if [ $UID -ne 0 ]; then
    echo 'fatal error: must be run as root!'
    exit 1
fi

cd `dirname "$0"`
echo 'copying files...'
mkdir -p "$INST_PATH"
mkdir -p "$CONFIG_PATH"
cp -v -f -t "$INST_PATH" ffbackup-client ffbackup-restore mail.py cron.sh
cp -v -n -t "$INST_PATH" ffbackup_mail.py
cp -v -n -t "$CONFIG_PATH" client.conf
cp -v -n -t "$CRON_JOB_PATH" ffbackup_cron
ln -v -f --symbolic "$INST_PATH/ffbackup_mail.py" "$CONFIG_PATH/mail.cfg"

echo
echo 'creating user ffbackup'
id -u ffbackup >/dev/null 2>&1 || useradd -c 'FFBackup System' -d /nonexistent -M -r -s /bin/false ffbackup

echo
echo 'installation finished'
