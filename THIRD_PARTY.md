# Сторонние компоненты

MIT в корне относится к собственному коду Capsula. Права и лицензии внешних
компонентов сохраняются. Необходимые готовые двоичные файлы включены
в `resources/`; их версии и SHA-256 закреплены в манифестах.
Скачанные для пересборки исходники и инструменты хранятся в `.cache/` вне Git.

| Компонент | Происхождение и лицензия |
| --- | --- |
| Go и Go-модули | `go.mod`, `go.sum`, тексты в `licenses/Go.txt` и `licenses/go/` |
| SHA512-crypt | Реализация musl из Zig 0.15.2, public domain; происхождение и изменения указаны в `native/sha512-crypt.c` |
| Dropbear 2026.94 | [Dropbear](https://matt.ucc.asn.au/dropbear/), MIT и BSD-совместимые условия компонентов; `licenses/Dropbear.txt` |
| Ядро Linux | [vk-capsula-mini-a113x-linux](https://github.com/comp18man/vk-capsula-mini-a113x-linux), ревизия `8d850405b091aaf217f8bb1bbdf22852f5cdb61e`; `licenses/Linux.txt`, `licenses/GPL-2.0.txt`, `licenses/Linux-syscall-note.txt` |
| libusb / libusb-compat | LGPL, `licenses/libusb.txt` и `licenses/libusb-compat.txt` |
| BusyBox, nano, htop | GPL; `licenses/toolkit/` |
| ncurses, Fastfetch, OpenSSH, curl, Mbed TLS | Условия компонентов в `licenses/toolkit/`; версии и исходники в `resources/stock-root/toolkit-sources.json` |
| Alpine minirootfs | Источник BusyBox и musl для начальной RAM-среды; версия, URL и SHA-256 в `native/sources.lock.json` |
| Entware | Внешний `opkg`, конфигурация и CA bundle; URL и SHA-256 в `resources/stock-root/entware-sources.json` |

Для GPL/LGPL-компонентов при распространении готовых сборок необходимо
сохранять соответствующие лицензии и обеспечивать доступ к соответствующим
исходникам и изменениям согласно условиям этих лицензий. Скрипты сборки,
параметры и изменения проекта сохранены в `native/`.

## Linux USB-помощник `update`

Linux-версия использует готовую Amlogic USB-утилиту `update` v1.5.
SHA-256 закреплён в `resources.lock.json` и `internal/capsula/resources.go`.
Исходное дерево распространения:
[Stane1983/aml-linux-usb-burn](https://github.com/Stane1983/aml-linux-usb-burn),
ревизия `257b808ba8550db023875b139db2eca9d11d55a4`.

Исходники и разрешение на распространение этой готовой утилиты в проекте
отсутствуют. Копия хранится в `resources/update` и не покрывается MIT Capsula.
Наличие её копии в локальном комплекте ресурсов само по себе не предоставляет
права распространять её. Windows-версия использует Microsoft WinUSB
и этот компонент не содержит.
