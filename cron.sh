#!/bin/sh

cd /
if [ "$#" -eq 1 ]; then
    ffbackup_config="$1"
elif [ "$#" -eq 0 ]; then
    ffbackup_config=/etc/ffbackup/client.conf
else
    echo "usage: $0 CONFIG_PATH"
    exit 1
fi

backup_log=$(/opt/ffbackup/ffbackup-client -f "$ffbackup_config" 2>&1)
ret="$?"
if [ "$ret" -ne 0 ]; then
    printf "code: %s\n\n%s" "$ret" "$backup_log" \
        | python /opt/ffbackup/mail.py
fi
