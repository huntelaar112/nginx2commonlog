#!/bin/bash
set -e

nginx2commonlog -i "/mnt/containerdata/nginxgen/var_log_nginx" -o "/var/log/nginx/access.log" -d "${DAYS}" &

if [ "${1:0:1}" = '-' ]; then
    set -- telegraf "$@"
fi

if [ $EUID -ne 0 ]; then
    exec "$@"
else
    # Allow telegraf to send ICMP packets and bind to privliged ports
    setcap cap_net_raw,cap_net_bind_service+ep /usr/bin/telegraf || echo "Failed to set additional capabilities on /usr/bin/telegraf"

    exec setpriv --reuid telegraf --init-groups "$@"
fi


