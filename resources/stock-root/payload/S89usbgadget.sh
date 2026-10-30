#!/bin/sh
# Start our optional service independently, then retain the original stock hook.
if [ "$1" = start ]; then
    (
        umask 077
        {
            echo 'CAPSULA_ROOT_BOOT_DIAGNOSTIC'
            /usr/lib/capsula-root/supervisor identity
            uname -r
            cat /proc/mounts
            /usr/lib/capsula-root/dropbearmulti dropbear -V
            /bin/sh /usr/lib/capsula-root/service start
            echo "service_start_rc=$?"
            /usr/lib/capsula-root/supervisor status
            echo "supervisor_status_rc=$?"
            sleep 5
            echo 'ENTROPY_AVAILABLE'
            cat /proc/sys/kernel/random/entropy_avail
            /bin/busybox logread | /bin/busybox grep -E 'dropbear|capsula-root|overlay'
            for p in /proc/[0-9]*/comm; do
                read -r name < "$p" || continue
                case "$name" in dropbearmulti|supervisor)
                    echo "$p:$name"
                    cat "${p%/comm}/wchan"
                    ;;
                esac
            done
        } > /data/.capsula-root-state/boot.log 2>&1
        /bin/sync
    ) </dev/null >/dev/null 2>&1 &
elif [ "$1" = stop ]; then
    /usr/lib/capsula-root/supervisor stop </dev/null >/dev/null 2>&1
fi
. /rom/etc/init.d/S89usbgadget.sh
