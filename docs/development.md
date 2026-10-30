# Разработка

## Основная программа

`make build` собирает программу на текущей системе, `make build-windows` —
Windows x86_64 из Linux. Go-модули закреплены в `go.mod` и `go.sum`.
CGO отключён. Все результаты сборки находятся в `build/` и не входят в Git.

`make test` запускает автоматические тесты. Нужные им вспомогательные программы
и RAM-образ уже включены в репозиторий. `make test-full` сначала проверяет
наличие и контрольные суммы ресурсов, затем запускает тесты.
SSH-тестам нужен доступ к localhost. Ни одна из этих команд не работает
с подключённой колонкой.

## Нативные компоненты

Скрипты в `native/` рассчитаны на Linux x86_64. Дополнительно нужны
Zig 0.15.2, GNU Make, LLVM (`llvm-ar`, `llvm-ranlib`, `llvm-objcopy`,
`llvm-strip`), autotools, CMake, pkg-config и ncurses (`tic`, `infocmp`).
Скрипт загрузки проверяет SHA-256 из `native/sources.lock.json`.
Скачанные архивы, компилятор и промежуточные результаты находятся в `.cache/`.

```sh
python3 -B native/fetch.py toolchain
python3 -B native/build-helpers.py
python3 -B native/build-windows-helpers.py

python3 -B native/fetch.py dropbear
python3 -B native/build-dropbear.py

python3 -B native/fetch.py toolkit
python3 -B native/build-toolkit.py --arch aarch64

python3 -B native/fetch.py usb
python3 -B native/build-host-usb.py
```

Путь к уже установленному Zig можно передать через `ZIG=/path/to/zig`.
Помощники записываются в `resources/stock-root/bin/`, toolkit — в
`resources/stock-root/toolkit/`; рядом обновляются соответствующие манифесты.
Для сборки Dropbear также нужен загруженный архив Zig из группы `toolchain`.

Исходник `native/sha512-crypt.c` основан на реализации musl из Zig 0.15.2.
Скрипт Dropbear содержит изменения проверки SHA512-crypt, длины пароля,
настроек аутентификации и пути SFTP-сервера. Эти изменения применяются
к чистому закреплённому исходному архиву, а не к содержимому тестового стенда.

## RAM-среда

```sh
python3 -B native/fetch.py ramboot
python3 -B native/ramboot/build-ramroot.py
```

Скрипт использует закреплённые исходные DTB и Alpine minirootfs, скрипты
из `resources/ramboot/` и готовое ядро. Он пересобирает initramfs и DTB,
отключающий постоянные накопители для начального RAM-сеанса.
Программа формирует последующие RAM-среды в `internal/capsula/ram.go`.

Ядро `Image` поставляется готовым внешним компонентом. Его исходный
репозиторий, ревизия и источник образа записаны в `native/sources.lock.json`;
конфигурации находятся в `native/kernel/`. Побайтовая воспроизводимость
внешнего готового ядра этим проектом не гарантируется.
Linux USB-помощник `update` также является внешним готовым компонентом;
он не собирается скриптами проекта. См. `THIRD_PARTY.md`.

## Изменение комплекта ресурсов

После намеренной пересборки внешних компонентов нужно обновить их манифесты
и соответствующие размеры, SHA-256 и режимы в `resources.lock.json`.
`make check-resources` проверяет соответствие файлов lock-файлу.
Изменённые ресурсы и манифесты добавляются в Git вместе.

Обычное изменение Go-кода, включая исправление обработки CRLF в хэше пароля,
не требует смены комплекта ресурсов.
