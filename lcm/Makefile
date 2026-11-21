# Локальна розробка. Секрети і дані — у .dev/ (не комітиться).
export DATABASE_URL ?= postgres://lcm:dev@127.0.0.1:55432/lcm?sslmode=disable
export MASTER_KEY_FILE ?= $(CURDIR)/.dev/master.key
export DATA_DIR ?= $(CURDIR)/.dev/data
export LISTEN_ADDR ?= 127.0.0.1:8090
export PUBLIC_URL ?= http://localhost:8090
export COOKIE_INSECURE ?= 1

.PHONY: db build test compat dev init run run-lan pubkeys user env

db:
	docker compose -f deploy/docker-compose.dev.yml up -d

build:
	go build -o bin/ ./cmd/...

test:
	go test ./...

# Тести сумісності з espsecure.py та esp_enc_img_gen.py (потрібен Python з cryptography).
compat:
	ZIR_COMPAT_PYTHON=$(ZIR_COMPAT_PYTHON) ZIR_ENC_IMG_GEN=$(ZIR_ENC_IMG_GEN) go test -run Compat -v ./internal/crypto/...

init: build
	mkdir -p .dev/data
	test -f .dev/master.key || bin/lcmctl gen-master-key .dev/master.key
	bin/lcmctl init-keys

run: build
	bin/lcm

# Доступ із локальної мережі (прилад ходить на http://<IP цього комп'ютера>:8090).
run-lan: build
	LISTEN_ADDR=0.0.0.0:8090 bin/lcm

# Публічні ключі для прошивки: .dev/pubkeys/zir_server_keys.h
pubkeys: build
	bin/lcmctl export-pubkeys .dev/pubkeys

# Створити користувача: make user LOGIN=root ROLES=superadmin NAME=Ім'я  (пароль спитає)
LOGIN ?= root
ROLES ?= superadmin
NAME ?=
user: build
	bin/lcmctl create-user -login "$(LOGIN)" -name "$(NAME)" -roles "$(ROLES)"

# Змінні для ручного запуску lcmctl/lcm/devicesim з терміналу:  eval "$$(make -s env)"
env:
	@echo "export DATABASE_URL='$(DATABASE_URL)' MASTER_KEY_FILE='$(MASTER_KEY_FILE)' DATA_DIR='$(DATA_DIR)' LISTEN_ADDR='$(LISTEN_ADDR)' PUBLIC_URL='$(PUBLIC_URL)' COOKIE_INSECURE='$(COOKIE_INSECURE)'"
