# ZIR — контекст системы

ZIR-3M — портативный детектор FPV-видеосигналов на ESP32. Система из трёх частей, каждая в своём
каталоге. Этот репозиторий (`zir-lcm`) — сервер LCM и документы всей системы.

## Где что лежит

| Часть | Путь | Что это |
|---|---|---|
| **LCM** (ZIR LifecycleManager) | `/Users/mac/Documents/Projects/zir-lcm/lcm` | Сервер на Go: регистрация приборов, подписанные конфиги, сборки и релизы, OTA с шифрованием под прибор, админка |
| **Прошивка** | `/Users/mac/Documents/PlatformIO/Projects/ZIR_3M` | ESP-IDF 6.0.1 через PlatformIO, ESP32 classic WROOM 4 МБ, ревизия чипа v3.1 |
| **Bootstrap** | `ZIR_3M/bootstrap` (+ `components/lcm_client`) | Первая прошивка: Wi-Fi, регистрация, установка. `docs/bootstrap.md` |
| **Клиент LCM в прошивке** | `ZIR_3M/components/lcm_service` | Обновления, регистрация, ограничение сборки для разработки. Сервер для сборки (и bootstrap, и рабочей прошивки) — `ZIR_3M/lcm_server/` (`url.txt`, `zir_server_keys.h`, не в git) или `ZIR_LCM_SERVER` |
| **Веб-морда прибора** | `/Users/mac/Documents/Projects/zir-web-ui` | Vue 3 + Vite + TS, хранится на приборе в разделе `www`, отдаётся с прибора |

Внешнее: VPS с доменом и Traefik (Let's Encrypt), репозитории на GitHub (приватные).

## Документы

В этом репозитории (основные решения — здесь):
- `ARCHITECTURE.md` — архитектура сервера, уровни защиты L0/L1/L2, модель данных, протоколы (раздел 7).
- `FIRMWARE_REQUIREMENTS.md` — что должна уметь прошивка; раздел 1 «Запрещено на L0» (опции, прожигающие eFuse).
- `DEVICE_PROTOCOL.md` — точные форматы `/dev/v1`: подпись запросов `X-Zir-Sig`, ECIES «zir box», JWS, `.zwww`.
- `PLAN.md` — план и статус MVP, отличия реализации от архитектуры, очередь после MVP.
- `ARCHITECTURE_DRAFT.md` — история вопросов и ответов владельца (обоснование решений). Только дописывать.
- `lcm/README.md` — запуск LCM локально и на VPS.

В прошивке:
- `docs/bootstrap.md` — bootstrap и общий клиент `lcm_client`; проверка без железа `test/lcm_host/run.sh`.
- `docs/lcm-build.md` — пошаговое задание: сборка прошивки под LCM (Kconfig, профили, `zir_custom_desc_t`, разделы, подпись).
- `docs/web-ui-brief.md` — контракт API прибора для веб-морды (источник правды — код прошивки). Копия — `zir-web-ui/plan.md`, держать одинаковыми.
- `TODO` — идеи владельца по прошивке.

## Ключевые решения (не пересматривать без владельца)

- **Уровень защиты L0: eFuse не прожигаются.** Прибор можно перепрошить по USB. Подпись OTA —
  `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT` + RSA-3072, только в боевой сборке. Опции Secure Boot,
  Flash Encryption, anti-rollback и отключение UART-загрузки не включать.
- **Сборка для разработки привязана к серверу:** без синхронизации (сессия при `"dev": true` в конфиге)
  работает не больше часа наработки, потом обнаружение останавливается; Wi-Fi в ней включён при старте.
- **Прошивку не установить на незарегистрированный прибор:** образ шифруется ключом `K_ota` конкретного
  прибора (`esp_encrypted_img`) и подписан сервером.
- **Сборка для разработки** (`CONFIG_ZIR_DEV_BUILD=y`, PlatformIO `esp32dev`): без проверки подписи,
  инженерный режим из меню прибора. Сервер такие образы никогда не подписывает. По OTA доставляет их
  только приборам разработчика (`"dev": true` в подписанном конфиге, ставит только superadmin),
  зашифрованными `K_ota`. Критическая dev-сборка ставится сразу, без проверки заряда; прибор
  разработчика опрашивает сервер раз в 30 с.
- **Веб-морда — архив `www.tar`**, распаковывает прошивка. Принимается только подписанный
  (хеш в подписанном манифесте или контейнер `.zwww`). В архиве обязателен несжатый `manifest.json`
  с `version` и `www_api`.
- **Жёсткие (подписанные) параметры** — только установленные модули и их частоты. Атенюаторы,
  калибровка АКБ и параметры детектора — мягкие, меняются в инженерной сессии.
- **Пароль точки доступа** `zir-XXXXX` (уникальный, генерирует bootstrap). Пользователь может сменить,
  прибор сообщает новый серверу. Через точку доступа — только WPA2, через роутер — HTTP Basic.
- **Критические релизы** ставятся сами при заряде АКБ ≥ 20 %. Остальные — по кнопке (≥ 30 %).
- Модули: FT3500 3.3 ГГц (channel 2), RX5808 5.8 ГГц (channel 1, есть всегда), TA8804 1.2 ГГц (channel 0).
  Профиль по умолчанию — `zir3m-full`.

## LCM: устройство кода

`lcm/` — Go-модуль `zir/lcm`, Go 1.26.
- `cmd/lcm` — сервер (админка + device API), `cmd/lcmctl` — CLI администрирования, `cmd/devicesim` — симулятор прибора.
- `internal/core` — вся доменная логика; `internal/httpapi` — `/dev/v1`; `internal/web` — админка (шаблоны, без JS).
- `internal/crypto/*` — `espsig` (Secure Boot V2), `encimg` (`esp_encrypted_img`), `jws`, `ecies`, `envelope`, `appdesc`.
- `internal/signer` — ключи сервера (в БД под мастер-ключом). `internal/devicesim` — эталон клиентской части протокола.
- `internal/flashimg` — разбор образа bootstrap с 0x0. Админка без JS, кроме «Прошивка USB»
  (`internal/web/static/flash.js` + esptool-js в `static/esptool/`, Web Serial).
- `migrations/` — goose, встроены в бинарник. `internal/e2e` — сквозной тест.

## Запуск и проверка

```sh
cd lcm
make db           # PostgreSQL в Docker, 127.0.0.1:55432 (контейнер deploy-postgres-1, пользователь/БД lcm)
make init         # мастер-ключ .dev/master.key + ключи сервера
make user LOGIN=root ROLES=superadmin
make run          # http://localhost:8090 (порт 8080 на этой машине занят другим контейнером)
make run-lan      # доступ с прибора из локальной сети
make pubkeys      # .dev/pubkeys/zir_server_keys.h для прошивки
eval "$(make -s env)"   # переменные для ручного запуска bin/lcmctl, bin/devicesim
```

Тесты:
- `go test ./...`;
- сквозной: `TEST_DATABASE_URL='postgres://lcm:dev@127.0.0.1:55432/postgres?sslmode=disable' go test ./internal/e2e/`;
- совместимость с инструментами Espressif: `ZIR_COMPAT_PYTHON` (Python с `cryptography`) и `ZIR_ENC_IMG_GEN`
  (путь к `esp_enc_img_gen.py` из `espressif/idf-extra-components`). `espsecure` берётся из
  `~/.platformio/packages/tool-esptoolpy`.
- клиент прошивки против сервера: `ZIR_3M/test/lcm_host/run.sh` (с `TEST_DATABASE_URL` — ещё и
  `TestFirmwareClient`); векторы делает `go run ./cmd/fwvectors`.

`bin/lcmctl inspect-app <firmware.bin>` — без БД показывает, примет ли сервер образ.

## Окружение и подводные камни

- ESP-IDF и esptool — только внутри PlatformIO: `~/.platformio/packages/framework-espidf` (6.0.1),
  `~/.platformio/packages/tool-esptoolpy`, `~/.platformio/platforms/espressif32`. `idf.py` в PATH нет.
- PlatformIO кеширует конфиг в `sdkconfig.<env>`: правки `*.defaults` не применяются, пока он есть.
- PlatformIO собирает `firmware.bin` своим вызовом esptool, без `--secure-pad-v2`. Это допустимо.
- Шелл — zsh: не называть переменные `path` (связана с `PATH`).
- mbedTLS в ESP-IDF 6 — версия 4.0: низкоуровневые API (`mbedtls_ecdsa_*`, `mbedtls_gcm_*`) закрыты, только PSA Crypto.
- Bootstrap: `pio run -d bootstrap`. Не включать в нём `CONFIG_SECURE_SIGNED_APPS_*` (подпись проверяется в коде).
- Сложные python-heredoc с кавычками в Bash может заблокировать проверка безопасности — писать скрипт в файл.
- `zir-lcm` пока не git-репозиторий. В прошивке и веб-морде git есть, коммитить только по просьбе.

## Язык

- Общение с владельцем и документы в `zir-lcm` — на русском.
- Интерфейсы (админка LCM, веб-морда, экран прибора) — на украинском.
- Комментарии в коде — на английском.
