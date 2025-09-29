# Инструкция по настройке OpenID Connect для 1С через Authelia

[Публикация на infostart](https://infostart.ru/public/2488511/)

## Содержание

1. [Введение](#введение)
2. [Установка и настройка Authelia](#установка-и-настройка-authelia)
   - [Подготовка](#подготовка)
   - [Конфигурация](#конфигурация)
   - [Пользователи](#пользователи)
   - [Запуск](#запуск)
3. [Настройка Nginx Proxy Manager](#настройка-nginx-proxy-manager)
   - [Настройка прокси-хоста для Authelia](#настройка-прокси-хоста-для-authelia)
   - [Настройка прокси-хоста для 1С](#настройка-прокси-хоста-для-1с)
4. [Настройка 1С](#настройка-1с)
   - [Настройка веб-публикации](#настройка-веб-публикации)
   - [Настройка пользователей](#настройка-пользователей)
5. [Настройка 2FA](#настройка-2fa)
   - [Предварительная настройка](#предварительная-настройка)
   - [Time-based One-time Password](#time-based-one-time-password)
6. [Возможные проблемы и решения](#возможные-проблемы-и-решения)
   - [Ошибка, что в токене нет ключа сопоставления](#ошибка-что-в-токене-нет-ключа-сопоставления)

## Введение

Данная инструкция описывает настройку единой аутентификации (SSO) для информационных баз 1С:Предприятие через OpenID Connect с использованием Authelia в качестве провайдера идентификации.

OpenID Connect (OIDC) — это протокол аутентификации, построенный поверх OAuth 2.0, который позволяет клиентским приложениям проверять личность пользователя на основе аутентификации, выполненной сервером авторизации.

В примере используется домен: `example.ru` и информационная база: `1c_smb_demo1`.
Эти параметры нужно заменить на свои.

## Установка и настройка Authelia

### Подготовка

- Клонируйте репозиторий

```bash
git clone https://github.com/komarovps/onec-authelia.git
cd onec-authelia
```

- Сгенерируйте секреты, которые будут проброшены в Authelia

```bash
openssl rand -hex 64 > authelia/secrets/JWT_SECRET
openssl rand -hex 64 > authelia/secrets/STORAGE_ENCRYPTION_KEY
openssl rand -hex 64 > authelia/secrets/SESSION_SECRET
openssl rand -hex 64 > authelia/secrets/OIDC_HMAC_SECRET

openssl genrsa -out authelia/secrets/rsa.2048.key 2048
```

- На секреты выдать права только владельцу

```bash
chmod 600 authelia/secrets/*
```

### Конфигурация

Конфигурационный файл Authelia: `authelia/config/configuration.yml`

Для 1С нужно выбрать тип конфигурации в зависимости от версии платформы:

- До версии 8.3.20: `configuration_token.yml` - используется [Implicit Flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth)

  ```bash
  mv authelia/config/configuration_token.yml authelia/config/configuration.yml
  rm authelia/config/configuration_code.yml # лишний конфиг удаляем
  ```

- После 8.3.20: `configuration_code.yml` - используется [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)

  ```bash
  mv authelia/config/configuration_code.yml authelia/config/configuration.yml
  rm authelia/config/configuration_token.yml # лишний конфиг удаляем
  ```

### Пользователи

Файл с пользователями: `authelia/config/user_database.yml`

Вместо пароля нужно указывать хэш.
Получить хэш можно выполнив:

```bash
docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password 'password'
```

где вместо `password` указать пароль или воспользоваться [сервисом](https://argon2.online/)

### Запуск

- Запустите docker compose c Authelia:

```bash
docker compose up -d
```

- Проверьте, что конфигурация oidc валидна перейдя в браузере по адресу `https://auth.example.ru/.well-known/openid-configuration`. В ответе должен появится json с конфигурацией.

- Проверьте лог контейнера `authelia`:

```bash
docker logs -f authelia
```

при успешном запуске в логе будет что-то вроде:

```text
time="" level=info msg="Authelia v4.39.10 is starting"
time="" level=info msg="Log severity set to info"
time="" level=info msg="Storage schema is being checked for updates"
time="" level=info msg="Storage schema is already up to date"
time="" level=info msg="Startup complete"
time="" level=info msg="Listening for non-TLS connections on '[::]:9091' path '/'" server=main service=server
```

## Настройка Nginx Proxy Manager

Nginx Proxy Manager используется для проксирования запросов и управления SSL-сертификатами.
[Документация по настройке NPM для Authelia](https://www.authelia.com/integration/proxies/nginx-proxy-manager/).

### Настройка прокси-хоста для Authelia

1. Создайте snippet `proxy.conf` на сервере NPM:

    ```bash
    sudo mkdir -p /data/nginx/custom/snippets
    sudo nano /data/nginx/custom/snippets/proxy.conf
    ```

    вставьте в `proxy.conf`:

    ```nginx
    ## Headers
    proxy_set_header Host $host;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-URI $request_uri;
    proxy_set_header X-Forwarded-Ssl on;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;

    ## Basic Proxy Configuration
    client_body_buffer_size 128k;
    proxy_next_upstream error timeout invalid_header http_500 http_502 http_503; ## Timeout if the real server is dead.
    proxy_redirect  http://  $scheme://;
    proxy_http_version 1.1;
    proxy_cache_bypass $cookie_session;
    proxy_no_cache $cookie_session;
    proxy_buffers 64 256k;

    ## Trusted Proxies Configuration
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    ## Advanced Proxy Configuration
    send_timeout 5m;
    proxy_read_timeout 360;
    proxy_send_timeout 360;
    proxy_connect_timeout 360;
    ```

2. Создайте новый Proxy Host в Nginx Proxy Manager:

    - **Domain Names**: `auth.example.ru`
    - **Scheme**: `http`
    - **Forward Hostname/IP**: `IP_адрес_сервера_Authelia`
    - **Forward Port**: `9091`
    - Включите **Cache Assets**, **Block Common Exploits**, **Websockets Support**

3. Включите SSL:

    - Перейдите на вкладку **SSL**
    - Выберите **SSL сертификат** (его нужно сделать)
    - Включите **Force SSL**

4. Настройте Advanced конфигурацию:

    - Перейдите на вкладку **Advanced**
    - Добавьте следующую конфигурацию:

    ```nginx
    location / {
        include /data/nginx/custom/snippets/proxy.conf;
        proxy_pass $forward_scheme://$server:$port;
    }
    ```

### Настройка прокси-хоста для 1С

1. Создайте новый Proxy Host для 1С:

    - **Domain Names**: `1c.example.ru`
    - **Scheme**: `http`
    - **Forward Hostname/IP**: `IP_адрес_сервера_1С`
    - **Forward Port**: `80` или порт веб-сервера 1С

2. Настройте SSL аналогично Authelia

3. В Advanced добавьте:

    ```nginx
    location / {
        include /data/nginx/custom/snippets/proxy.conf;
        proxy_pass $forward_scheme://$server:$port;
    }
    ```

## Настройка 1С

### Настройка веб-публикации

Опубликовать базу на веб-сервере и в `default.vrd` веб-публикации добавить:

- Для `Authorization Code Flow`:

```xml
  <openidconnect>
    <providers>
      <![CDATA[
        [
            {
                "name": "Authelia",
                "title": "Authelia",
                "authenticationClaimName": "email",
                "authenticationUserPropertyName": "name",
                "discovery": "https://auth.example.ru/.well-known/openid-configuration",
                "clientconfig": {
                    "authority": "https://auth.example.ru",
                    "client_id": "1c_smb_demo1",
                    "redirect_uri": "https://1c.example.ru/smb_demo1/authform.html",
                    "response_type": "code",
                    "scope": "email openid profile",
                    "filterProtocolClaims": false,
                    "loadUserInfo": true
                }
            }
        ]
        ]]>
    </providers>
    <allowStandardAuthentication>true</allowStandardAuthentication>
  </openidconnect>
```

- Для `Implicit Flow`:

```xml
  <openidconnect>
    <providers>
      <![CDATA[
        [
            {
                "name": "Authelia",
                "title": "Authelia",
                "authenticationClaimName": "email",
                "authenticationUserPropertyName": "name",
                "discovery": "https://auth.example.ru/.well-known/openid-configuration",
                "clientconfig": {
                    "authority": "https://auth.example.ru",
                    "client_id": "1c_smb_demo1",
                    "redirect_uri": "https://1c.example.ru/smb_demo1/authform.html",
                    "response_type": "id_token token",
                    "scope": "email openid",
                    "filterProtocolClaims": false,
                    "loadUserInfo": true
                }
            }
        ]
        ]]>
    </providers>
    <allowStandardAuthentication>true</allowStandardAuthentication>
  </openidconnect>
```

Описание элемента `openidconnect` на [ИТС](https://its.1c.ru/db/v8327doc#bookmark:adm:TI000000845).

### Настройка пользователей

В конфигураторе базы 1С, в настройках пользователя:

1. Включить **Аутентификация OpenID Connect**
2. Заполнить поле **Адрес электронной почты**

## Настройка 2FA

### Предварительная настройка

Перед настройкой 2FA обязательно настройте механизм оповещений через `smtp`, т.к. на почту пользователя будут отправляться данные для начальной настройки.

Пример с почтовым сервером `yandex`:

- Создайте файл для хранения пароля

```bash
touch authelia/secrets/yandex_smtp_password
chmod 600 authelia/secrets/yandex_smtp_password
nano authelia/secrets/yandex_smtp_password # указываем пароль
```

- Добавьте в `configuration.yml`:

```yaml
notifier:
  disable_startup_check: false

  smtp:
    address: 'submissions://smtp.yandex.ru:465'
    timeout: '10s'
    username: 'auth.robot@yandex.ru'
    password: {{ secret "/secrets/yandex_smtp_password" }}
    sender: 'Authelia <auth.robot@yandex.ru>'
    identifier: '1c.example.ru'
    subject: '[Authelia] {title}'
    startup_check_address: 'auth.robot@yandex.ru'
    disable_require_tls: false
    disable_html_emails: false
    tls:
      server_name: 'smtp.yandex.ru'
      skip_verify: false
      minimum_version: 'TLS1.2'
```

### Time-based One-time Password

- Для включения totp добавьте в `configuration.yml`

```yaml
...
totp:
  issuer: auth.example.ru
  period: 30
...
```

и включите второй фактор для клиента:

```yaml
identity_providers:
  oidc:
  ...
    clients:
      - client_id: 1c_smb_demo1
        authorization_policy: 'two_factor'
  ...
```

## Возможные проблемы и решения

### Ошибка, что в токене нет ключа сопоставления

!!! Только для Implicit Flow, т.е. если клиент настроен на:

```yaml
  response_types: 
    - 'id_token token'
    - 'token'
```

Для `response_types: code` этот способ не работает.

При успешной аутентификации в Authelia, 1С получает токен с данными о пользователе. Чаще всего далее идентификация пользователя 1С выполняется по email. Этой информации может не быть в токене.

Чтобы понять, что есть в токене, надо его получить и расшифровать. Тут на помощь приходит декодер токена: [https://jwt.ms/](https://jwt.ms/)

1. В `configuration.yml` раскомменитруем `redirect_uris` для отладки:

    ```yaml
    clients:
    ...
      - client_id: 1c_smb_demo1
        redirect_uris:
            - 'https://1c.example.ru/smb_demo1/authform.html'
            - 'https://jwt.ms' # Для отладки содержимого jwt
    ...
    ```

2. Перезагружаем контейнер, чтобы перезагрузился конфиг.

3. Открываем bash и готовим url для отладки.

    ```bash
    STATE=$(openssl rand -hex 16); NONCE=$(openssl rand -hex 16)

    # В параметре запроса `client_id` установить свой `id` из `configuration.yml`
    AUTH_URL="https://auth.example.ru/api/oidc/authorization?client_id=1c_smb_demo1&redirect_uri=https%3A%2F%2Fjwt.ms&response_type=id_token%20token&scope=openid%20email%20profile&state=${STATE}&nonce=${NONCE}"

    echo "$AUTH_URL"
    ```

4. Открываем полученуую ссылку в браузере

Пример ответа:

```json
{
  "alg": "RS256",
  "kid": "main",
  "typ": "JWT"
}.{
  "amr": [
    "pwd",
    "kba"
  ],
  "at_hash": "Bu6HQEvOIOQirrPlQFbecA",
  "aud": [
    "1c_smb_demo1"
  ],
  "auth_time": 1758204652,
  "azp": "1c_smb_demo1",
  "exp": 1758208690,
  "iat": 1758205090,
  "iss": "https://auth.example.ru",
  "jti": "0a902176-d2f2-4636-83ff-e606654290f8",
  "nonce": "5fbcbccbed06f309dcc7bb2aeee2027d",
  "sub": "3e403f57-086c-47f5-b969-f485bd9223f9"
}.[Signature]
```

Видно, что в свойствах нет информации о пользователе.

Управлять содержимым токена можно через свойство `claims_policies`. Добавляем его в `configration.yml`:

```yaml
...
identity_providers:
  oidc:
    ...
    claims_policies:
      id_token_with_email:
        id_token:
          - email
          - email_verified
          - preferred_username
          - name
    clients:
      - client_id: 1c_smb_demo1
        claims_policy: id_token_with_email
        ...
```

Повторяем п.3 и получаем токен с дополненной информацией:

```json
{
  "alg": "RS256",
  "kid": "main",
  "typ": "JWT"
}.{
  "amr": [
    "pwd",
    "kba"
  ],
  "at_hash": "qvazQ3vFLW7r-8KWm_-c7g",
  "aud": [
    "1c_smb_demo1"
  ],
  "auth_time": 1758294170,
  "azp": "1c_smb_demo1",
  "email": "ps.komarov@yandex.ru",
  "email_verified": true,
  "exp": 1758297771,
  "iat": 1758294171,
  "iss": "https://auth.example.ru",
  "jti": "48285920-d2a9-4249-bf62-1098349f3ae3",
  "name": "Pavel Komarov",
  "nonce": "5fbcbccbed06f309dcc7bb2aeee2027d",
  "preferred_username": "pskomarov",
  "sub": "3e403f57-086c-47f5-b969-f485bd9223f9"
}.[Signature]
```

С таким токеном уже можно в 1С.

## Полезные ссылки

- [Документация OpenId Connect](https://openid.net/specs/openid-connect-core-1_0.html)
- [ИТС. Описание элемента openidconnect](https://its.1c.ru/db/v8327doc#bookmark:adm:TI000000845)
- [ИТС. Настройка keycloak](https://its.1c.ru/db/metod8dev#content:5972:hdoc:keycloak_sample:keycloak)
- [ИТС. Документация по настройке OpenId Connect в 1С:Фреш](https://its.1c.ru/db/fresh#content:19956766:hdoc:issogl1_h1e1l9ae)
- [Authelia. OpenId Connect](https://www.authelia.com/configuration/identity-providers/openid-connect)
- [Authelia. Настройка NPM](https://www.authelia.com/integration/proxies/nginx-proxy-manager/)
- [Тонкости авторизации: обзор технологии OAuth 2.0](https://habr.com/ru/companies/dododev/articles/520046/)
