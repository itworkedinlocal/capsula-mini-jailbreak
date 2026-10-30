#!/bin/sh
# Owned overlay: stock telemetry returns when this file is removed by rollback.
BB=/usr/lib/capsula-root/busybox
case "${1:-start}" in
    start|stop|restart)
        "$BB" killall -TERM telemetryd 2>/dev/null || :
        attempt=0
        while "$BB" killall -0 telemetryd >/dev/null 2>&1; do
            [ "$attempt" -lt 5 ] || break
            "$BB" sleep 1
            attempt=$((attempt + 1))
        done
        if "$BB" killall -0 telemetryd >/dev/null 2>&1; then
            "$BB" killall -KILL telemetryd 2>/dev/null || :
            "$BB" sleep 1
        fi
        if "$BB" killall -0 telemetryd >/dev/null 2>&1; then
            printf 'Не удалось остановить telemetryd.\n' >&2
            exit 1
        fi
        ;;
    status)
        if "$BB" killall -0 telemetryd >/dev/null 2>&1; then
            printf 'telemetryd работает.\n'; exit 1
        fi
        printf 'Телеметрия отключена.\n'
        ;;
    *) printf 'usage: telemetry start|stop|restart|status\n' >&2; exit 2 ;;
esac
