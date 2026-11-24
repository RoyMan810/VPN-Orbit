# Разработка VPN-Orbit

## Где что находится

| Путь | Назначение |
| --- | --- |
| [`vpn_orbit/`](vpn_orbit/) | Python-пакет: API, база, очередь, Worker и runtime. |
| [`web/`](web/) | React/TypeScript WebUI, сборка и браузерные тесты. |
| [`deploy/`](deploy/) и [`install`](install) | Публичная точка установки, сборка комплекта, Dockerfile и host-профили. Compose и Nginx генерируются установщиком. |
| [`remote/`](remote/) | Ограниченные SSH-gateways и helper-команды для управляемых VPS. |
| [`tests/`](tests/) | Python-тесты `app/`, `runtime/`, `tools/` и изолированные системные сценарии `lab/`. |
| [`tools/`](tools/) | Подготовка VPS, локальная диагностика и инструменты сопровождения репозитория. |
| [`docs/`](docs/) | Руководства для пользователей и администраторов. |

Рабочие пути `install`, `deploy/`, `remote/`, `tools/prepare_vps.py` и установленный CLI не меняются при переносе внутренних тестов. Runtime pins — в `requirements-app.txt`, тестовые — в `requirements-dev.txt`, линтер — в `requirements-quality.txt`. Согласуйте версии в этих файлах, `pyproject.toml` и [lock-файлах комплекта](deploy/).

## Локальные проверки

На Linux используйте Python 3.15.2 с SQLite ≥3.45. Из корня репозитория:

```sh
python3.15 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt -r requirements-quality.txt
python -m pip install --no-deps -e .
ruff check .
python tools/check_repository.py
```

Для crypto/runtime-тестов подготовьте `age` и `age-keygen` v1.3.2. Команда загрузки сверяет закреплённый SHA-256 до распаковки:

```sh
age_dir=$(mktemp -d)
python tools/fetch_age.py --output "$age_dir/age.tar.gz" &&
  tar --no-same-owner -xzf "$age_dir/age.tar.gz" -C "$age_dir" -- age/age age/age-keygen &&
  VPN_ORBIT_TEST_AGE_DIR="$age_dir/age" python -m unittest discover -s tests -t . -v
```

Для отдельного набора используйте `python -m unittest discover -s tests/app -t . -v` (или `tests/runtime`, `tests/tools`). [Инструкция WebUI](web/README.md) описывает `npm ci`, сборку и Playwright. Регрессионные тесты нужны для изменения поведения, а не для косметических правок. Не выполняйте системные сценарии из `tests/lab/` на рабочей машине или пользовательской VPS: они меняют окружение и запускаются в одноразовых GitHub-hosted VM.

## Ветки и PR

Создавайте короткоживущую ветку от `main`. В PR укажите изменения, выполненные проверки и ограничения. Дождитесь CI перед слиянием. Полный CI проверяет пакет и тесты, реальную установку с systemd/Compose, SSH и изоляцию процессов; отдельные workflows запускают WebUI и продуктовые сценарии. Branch maintenance удаляет только проверенные временные ветки со слитыми PR, используя lease на точную вершину.

Обновляйте существующее руководство вместе с изменением поведения. Планы и промежуточные отчёты остаются в истории Git. Не коммитьте ключи, базы, локальные сборки и артефакты тестов.
