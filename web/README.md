# WebUI VPN-Orbit

Для обычной [установки](../docs/installation.md) сборка и публикация автоматические. Пользовательские сценарии описаны в [руководстве по VPS](../docs/vps.md) и [руководстве по приложениям](../docs/applications.md).

## Сборка и браузерные тесты

Нужен Node.js 26; CI использует Node.js 26.13.0 и npm 12.2.2. Для браузерных тестов активируйте Python-окружение из [руководства разработчика](../CONTRIBUTING.md), чтобы команда `python` находила установленные зависимости. Тесты запускают локальный HTTPS на порту 4173 с одноразовой SQLite и тестовыми учётными записями. Нужны OpenSSL и Chrome/Chromium.

```sh
cd web
npm ci
npm run build
npx playwright install chromium --only-shell
npm test
```

Для уже установленного браузера, вместо загрузки Chromium укажите абсолютный путь, например `VPN_ORBIT_CHROMIUM="$(command -v google-chrome)" npm test`.

## Публикация при ручной установке

Используйте `dist/` из того же коммита, что и контроллер, или скачайте архив `vpn-orbit-webui-<commit>` из [успешного прогона WebUI](https://github.com/RoyMan810/VPN-Orbit/actions/workflows/web-ui.yml). Сверьте `source-commit.txt` с `source_commit` проверенного комплекта и распакуйте архив:

```sh
sha256sum -c SHA256SUMS && mkdir -p dist && tar -xzf webui.tar.gz -C dist
```

Публикуйте статику в корне того же HTTPS origin, который передан установщику контроллера. Проксируйте `/api/` к loopback API с исходным `Host`, перезаписанными `X-Forwarded-Proto: https` и `X-Forwarded-For` (фактический адрес клиента). Для Nginx используйте те же защитные заголовки, что в [конфигурации штатного bootstrap](../deploy/bootstrap.py). Node.js на сервере статики не нужен.
