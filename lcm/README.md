# LCM — ZIR LifecycleManager

Реєстрація приладів, підписані конфігурації, збірки й релізи, OTA з шифруванням образу під
конкретний прилад. Специфікація — `../ARCHITECTURE.md`, протокол приладу — `../DEVICE_PROTOCOL.md`,
план — `../PLAN.md`.

## Локальна розробка

Потрібні Go 1.26 і Docker.

```sh
make db        # PostgreSQL у Docker на 127.0.0.1:55432
make init      # .dev/master.key + ключі сервера в БД
make user LOGIN=root ROLES=superadmin   # спитає пароль (від 12 символів)
make run        # http://localhost:8090 ; make run-lan — доступ з локальної мережі для приладу
```

Відкрийте http://localhost:8090, увійдіть і налаштуйте TOTP (QR-код на першому вході).

Змінні середовища (`DATABASE_URL`, `MASTER_KEY_FILE`, `DATA_DIR`…) задає `Makefile`. Щоб запускати
`bin/lcmctl` чи `bin/devicesim` напряму з терміналу, спершу виконайте в каталозі `lcm`:

```sh
eval "$(make -s env)"
```

### Тести

```sh
make test                                                     # модульні
TEST_DATABASE_URL='postgres://lcm:dev@127.0.0.1:55432/postgres?sslmode=disable' go test ./internal/e2e/
# Сумісність з інструментами Espressif (Python з пакетом cryptography):
ZIR_COMPAT_PYTHON=/path/to/python ZIR_ENC_IMG_GEN=/path/to/esp_enc_img_gen.py make compat
```

`internal/e2e` проходить повний цикл через HTTP: дві реєстрації, релізи, beta/stable, критичний,
призначення інженером і відкат, закріплення, конфігурація, пароль, відкликання, перереєстрація, і
перевіряє, що образ одного приладу не розшифровується ключем іншого.

### Симулятор приладу

```sh
bin/lcmctl export-pubkeys .dev/pubkeys
bin/devicesim -server http://localhost:8090 -state dev1.json register   # покаже код, чекає підтвердження
bin/devicesim -server http://localhost:8090 -state dev1.json update     # перевірка й встановлення
bin/devicesim -server http://localhost:8090 -state dev1.json password нов-пароль-1
bin/devicesim -profile zir3m-full fake-app 1.0.0 app.bin                # фейковий образ для завантаження
bin/devicesim -dev fake-app main-test dev.bin                           # фейкова збірка для розробки
bin/devicesim -server http://localhost:8090 -state dev1.json watch      # прилад, що працює: перевірка кожні poll_after с
```

Прилад, що чекає реєстрації, з'являється в адмінці на вкладці «Реєстрація». «Додати» → код з виводу
`register` → профіль. Позначка «Прилад розробника» (лише superadmin) дозволяє йому збірки для розробки.

### Збірки для розробки

Адмінка → «Розробка»: завантажити `firmware.bin` з `esp32dev` (`CONFIG_ZIR_DEV_BUILD=y`), відмітити
прилади розробника, за потреби «Критична» (ставиться протягом ~30 с, без кнопки й без перевірки заряду).
З терміналу — токеном API (створюється там само, показується один раз):

```sh
export LCM_URL=http://localhost:8090 LCM_TOKEN=zirlcm_...
bin/lcmctl push-dev -devices ZIR-7K2Q9XM,ZIR-B4N8T0C -critical .pio/build/esp32dev/firmware.bin
bin/lcmctl push-dev -devices all firmware.bin    # усім приладам розробника профілю збірки
bin/lcmctl dev-devices                           # що на яких приладах
```

Клієнт прошивки (`ZIR_3M/components/lcm_client`) перевіряється проти цього сервера:
`ZIR_3M/test/lcm_host/run.sh` (вектори — `go run ./cmd/fwvectors`, протокол — `TestFirmwareClient`).
`lcmctl export-pubkeys` кладе в `zir_server_keys.h` і ключі підпису прошивок (`ZIR_KEYS_FWSIGN`) для bootstrap.

### Bootstrap і прошивка по USB з браузера

Bootstrap збирається для конкретного сервера (`ZIR_3M/lcm_server/`: `url.txt` і `zir_server_keys.h` з
`lcmctl export-pubkeys` саме цього сервера). Сервер приймає лише один образ з 0x0
`bootstrap/.pio/build/bootstrap/zir3m-bootstrap-<версія>.bin`. Він перевіряє розмітку (завантажувач,
таблиця розділів, `zir_bootstrap` в `ota_0`, 4MB), semver-версію і наявність ключа конфігурацій цього сервера.

```sh
bin/lcmctl push-bootstrap zir3m-bootstrap-0.1.0.bin   # або адмінка → «Збірки» → Bootstrap
pio run -d bootstrap -t lcm                            # у ZIR_3M: зібрати й завантажити (lcm_server/url.txt, token.txt)
bin/lcmctl bootstrap-builds
```

Адмінка → «Прошивка USB» (ролі manufacturer, engineer) або без входу — `https://<домен>/bootstrap`
(посилання є на сторінці входу; для виробництва без облікового запису): «Підключити» → обрати порт адаптера (CH340,
CP210x, FTDI) → «Прошити». Сторінка працює через Web Serial і esptool-js (`internal/web/static/esptool/`,
див. там README). Потрібні Chrome, Edge чи Opera на комп'ютері й HTTPS або localhost. Пишеться лише flash,
eFuse не чіпаються. Запис перевіряється MD5. Хто, коли і який bootstrap записав на чип з яким MAC,
видно в аудиті (`bootstrap.flash`; без входу — від `system` з IP, `"public": true`, не більше 200 на годину з IP).

## Робота з прошивкою

Покрокове завдання для репозиторію прошивки — `ZIR_3M/docs/lcm-build.md`.

1. `bin/lcmctl export-pubkeys <dir>` → `zir_server_keys.h` додати в прошивку.
2. Зібрати прошивку з `sdkconfig.release.defaults` і профілем, `CONFIG_ZIR_DEV_BUILD=n`.
   Перевірити без сервера: `bin/lcmctl inspect-app firmware.bin` (покаже профіль, версію, і чи прийме сервер).
3. Адмінка → «Збірки» → завантажити `firmware.bin` (і `firmware.elf`). Сервер перевірить
   `zir_custom_desc_t` і підпише образ.
4. Перший раз прилад прошивається по USB **підписаним** образом (кнопка `app.bin` у списку збірок
   або `lcmctl sign-app in.bin out.bin`), щоб він приймав OTA з сервера.
5. «Релізи» → створити (beta) → інженер ставить на прилад → «В stable».

## Розгортання на VPS

Потрібні: Docker з compose, працюючий Traefik у зовнішній мережі `traefik`, DNS-запис `A` для
`LCM_DOMAIN` на IP сервера. У `deploy/docker-compose.yml` звірте з налаштуваннями вашого Traefik
назву мережі, entrypoint (`websecure`) і certresolver (`letsencrypt`).

```sh
git clone <repo> /opt/zir-lcm && cd /opt/zir-lcm/lcm/deploy
cp .env.example .env && $EDITOR .env                      # LCM_DOMAIN, POSTGRES_PASSWORD='…' (з $ — лише в одинарних лапках)
docker compose build

# Каталоги і мастер-ключ. Контейнер працює від uid 65532 (distroless nonroot).
sudo mkdir -p /srv/lcm/{data,pg,secrets}
openssl rand -hex 32 | sudo tee /srv/lcm/secrets/master.key >/dev/null
sudo chown 65532:65532 /srv/lcm/data /srv/lcm/secrets/master.key
sudo chmod 600 /srv/lcm/secrets/master.key

docker compose up -d postgres
docker compose run --rm --entrypoint lcmctl lcm init-keys
docker compose run --rm --entrypoint lcmctl lcm export-signing-key /data/fw_sign.pem
sudo mv /srv/lcm/data/fw_sign.pem ~/   # → скопіювати офлайн (флешка + папір), потім видалити з сервера
docker compose run --rm --entrypoint lcmctl lcm export-pubkeys /data/pubkeys   # → zir_server_keys.h для прошивки
echo 'довгий-пароль-123' | docker compose run --rm -T --entrypoint lcmctl lcm create-user -login root -roles superadmin
docker compose up -d
curl https://<LCM_DOMAIN>/healthz      # ok
```

Оновлення сервера: `git pull && docker compose build && docker compose up -d` (міграції БД
застосовуються при старті).

**Обов'язково офлайн:** `master.key` і ключ підпису прошивок (`export-signing-key`). Втрата ключа
підпису = жоден прилад більше не оновиться по OTA.

Бекапи: `pg_dump` щоночі + `/srv/lcm/data/artifacts`. Мастер-ключ зберігається окремо від бекапів.
