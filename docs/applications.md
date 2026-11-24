# Управляемые приложения

[Документация](README.md)

VPN-Orbit устанавливает, запускает и удаляет только заранее настроенные Compose-профили. Он проверяет здоровье и принадлежность контейнеров. При удалении тома и сети сохраняются; обнаруженный дрейф или использование ресурсов чужими контейнерами блокирует операцию. Существующие внешние Compose-проекты можно проверять вручную, но нельзя автоматически принять под управление.

## Профили

| Профиль | Что подготовить |
| --- | --- |
| `remnawave-panel` | Домены панели (`domain`) и подписок (`subscription_domain`), `database_password`, `app_secret`, `metrics_password`. Профиль включает PostgreSQL и Redis. Настройте HTTPS reverse proxy к loopback-порту панели с корректными заголовками проксирования. |
| `remnawave-node` | `secret_key` из Remnawave Panel и `port`. Первичная регистрация остаётся в Remnawave Panel. Node использует host networking и `NET_ADMIN`; запускайте только на утверждённом выделенном хосте. |
| `bedolaga-bot` | HTTPS URL панели (`panel_url`), `panel_api_key`, `bot_token`, `admin_ids`, `database_password`, `api_token`, `jwt_secret`. Профиль включает свои PostgreSQL и Redis. |
| `bedolaga-cabinet` | Профиль `bedolaga-bot` в той же установке; дополнительных полей нет. Cabinet проксирует `/api/` в Bot со снятием префикса; проверка здоровья учитывает этот маршрут. |

Используйте [проверенные образы](../deploy/application-images.json) как исходный список. Указывайте разрешённую ссылку на репозиторий с `@sha256:…`, а не изменяемый тег. Образы подготавливаются для `linux/amd64`; их можно заранее скачать по тем же digest на одобренном хосте. Приложения, кроме Node, публикуют прикладные порты только на loopback.

Для Bot сначала подготовьте Panel и API-ключ. Используйте полноценное DNS-имя, при котором клиент проверяет сертификат. Для частного CA можно указать публичный сертификат в `panel_ca_pem`; он привязывается к спецификации и монтируется только для чтения. Не отключайте проверку TLS.

По умолчанию Bot использует long polling. Для webhook одновременно задайте `webhook_origin` и `webhook_secret`. HTTPS-адрес должен быть доступен Telegram. На reverse proxy передавайте в loopback-порт Bot только `POST /webhook` и сохраняйте `X-Telegram-Bot-Api-Secret-Token` без изменений. Не публикуйте служебные маршруты Bot через webhook vhost. Маршрут Cabinet `/api/` настраивается отдельно.

## Подготовка установки

1. На Docker-хосте установите доверенный пакет VPN-Orbit (минимум Python 3.13, для штатного runtime — Python 3.15 и SQLite ≥3.45). Подготовьте root-owned JSON режима `0600` с полями `v` (значение `1`), `id` (новый ULID), `profiles` (список имён), `images` (карта digest-ссылок, включая `postgres` и `redis`, когда они нужны) и `settings` (объект параметров для каждого профиля). Точные допустимые поля и ограничения — в [описании профилей](../vpn_orbit/app_profiles.py). Не храните этот файл в Git и не передавайте его в WebUI.
2. Выполните `sudo /opt/vpn-orbit/venv/bin/vpn-orbit-app configure --spec /root/orbit-app.json`, затем `sudo /opt/vpn-orbit/venv/bin/vpn-orbit-app status --id "$INSTALLATION_ID"`. Подставьте созданный ULID; сохраните digest спецификации.
3. Для управления из WebUI нужен отдельный SSH-аккаунт `vpn-orbit-apps` с отдельным ключом, только ключевой аутентификацией и без PTY, forwarding и user RC. Установите [apps-gateway](../remote/apps-gateway) как root-owned `/usr/local/libexec/vpn-orbit/apps-gateway` и назначьте его `ForceCommand`. Используйте только следующее sudo-правило:

   ```text
   vpn-orbit-apps ALL=(root) NOPASSWD: /opt/vpn-orbit/venv/bin/vpn-orbit-app-helper ""
   ```

4. В [защищённой политике контроллера](vps.md#подготовка-vps) укажите capability `apps.lifecycle`, `application_secret_ref` и соответствие `applications` между ID установки и digest. Импортируйте ключ через `import-application-key`. Право на один профиль не открывает shell, произвольный Compose YAML или доступ к другим установкам.

## Работа с приложениями

Откройте VPS в WebUI как владелец и перейдите в **Приложения**. Укажите ID и digest подготовленной установки, выберите действие, проверьте план и подтвердите его паролем. После отправки отслеживайте статус по ID задания. Если ответ не получен, не создавайте новую операцию вместо уже отправленной: [проверьте и сверьте результат](operations.md#неопределённый-результат).

Для работы локально на Docker-хосте у `vpn-orbit-app` есть `install`, `start` и `remove` с аргументами `--id`, `--digest` и `--operation` (ULID). Точный повтор операции с тем же ID возвращает сохранённый результат. `reconcile --id ID --operation ULID` читает состояние Docker, а не повторяет изменение. Не используйте локальный CLI, чтобы обойти блокировку контроллера. Если создание прервалось до записи идентификаторов контейнеров, операция остаётся в карантине для ручного расследования.

## Резервная копия PostgreSQL

`vpn-orbit-app-postgres` запускается только локально от root на Docker-хосте с проверенным `age` по пути `/opt/vpn-orbit/tools/age`. Команда повторно сверяет digest спецификации, идентификаторы контейнеров, томов и сети с журналом установки; неизвестная операция или чужой контейнер блокируют копирование. Выберите `panel-db` для Remnawave или `bot-db` для Bedolaga. `pg_dump` снимает согласованный снимок своей БД без копирования живого каталога PostgreSQL.

```sh
sudo vpn-orbit-app-postgres capture --id "$INSTALLATION_ID" --service panel-db \
  --spec-sha256 "$SPEC_SHA256" --archive /var/backups/orbit-apps/panel.age \
  --recipient "$AGE_RECIPIENT" --confirm
sudo vpn-orbit-app-postgres restore --id "$INSTALLATION_ID" --service panel-db \
  --spec-sha256 "$SPEC_SHA256" --archive /var/backups/orbit-apps/panel.age \
  --identity /run/private-recovery/backup.identity --sha256 "$ARCHIVE_SHA256" --confirm
```

Создайте каталог копий режима `0700`, сохраняйте хеш архива отдельно, а закрытый ключ держите вне хоста и подключайте только для восстановления. Восстановление расшифровывает снимок в tmpfs и транзакционно загружает его в отдельную БД `orbit_recovery_*` в том же PostgreSQL; рабочую БД `orbit` оно не меняет. Лимит снимка — 4 ГиБ, фактический предел зависит от свободного tmpfs. При сбое одноимённая тестовая БД может остаться для проверки; команда не удаляет её и не повторяет загрузку автоматически.

После проверки данных остановите все прикладные контейнеры проекта (PostgreSQL должен остаться запущенным). `vpn-orbit-app-postgres promote --id "$INSTALLATION_ID" --service panel-db --spec-sha256 "$SPEC_SHA256" --sha256 "$ARCHIVE_SHA256" --confirm` переключает БД двумя переименованиями в одной транзакции. При активном соединении PostgreSQL откажет. Прежняя БД сохраняется под `orbit_previous_*`; повтор команды с тем же хешем проверяет уже применённый результат, не переключая базы обратно. Перед запуском приложений проверьте данные и состояние интеграций. Redis, файловые тома и конфигурации приложений этой командой не восстанавливаются.

## Полная копия установки

Для переноса спецификации, Redis, файлов Bedolaga и томов PostgreSQL используйте локальный `vpn-orbit-app-archive`. Перед захватом штатно остановите **все** контейнеры проекта на его Docker-хосте. Команда откажет при активном контейнере, аварийном завершении PostgreSQL, чужом ресурсе или неизвестной операции. Это физическая копия **остановленных** томов: восстановление использует те же образы по digest, не обновляет PostgreSQL и не переносит чужие Docker-ресурсы.

```sh
sudo vpn-orbit-app-archive capture --id "$INSTALLATION_ID" --spec-sha256 "$SPEC_SHA256" \
  --archive /var/backups/orbit-apps/installation.age --recipient "$AGE_RECIPIENT" --confirm
sudo vpn-orbit-app-archive restore --archive /var/backups/orbit-apps/installation.age \
  --identity /run/private-recovery/backup.identity --sha256 "$ARCHIVE_SHA256" --confirm
```

Восстанавливайте только в новый проект с пустыми томами. Исходный ID сохраняется по умолчанию; `--id` при восстановлении создаёт проект с новым ID и требует отдельно утвердить новый digest и привязку в контроллере. Команда не запускает приложения, не удаляет старый проект и оставляет незавершённый новый проект заблокированным при сбое. Временные файлы размещаются в `/run` (tmpfs); контролируйте объём и шифруйте swap. До запуска оградите старую установку, проверьте конфигурацию и отдельно восстановите внешние reverse proxy, сертификаты и интеграции.
