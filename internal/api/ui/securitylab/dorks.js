// Recon Dork database for the Security Lab "Recon Dorks" tool.
// Dorks sourced from GHDB, HackerOne disclosures, and community methodologies
// (NahamSec, TCM, Jason Haddix) — adapted from the open-source KeenDork project
// (https://github.com/keen-i/keendork). {T} is replaced with the sanitized target.
// google-platform queries are wrapped in a Google search URL; all other platforms
// (github/shodan/wayback/crtsh/urlscan/censys/fofa/intx/grep) carry a full URL.
  window.DORKS_DB = {

    /* ══════════════════════════════ CRITICAL ══════════════════════════════ */
    critical: [
      {
        title: '.env Files with Secrets',
        icon: '⚙️',
        platforms: ['google'],
        query: 'site:{T} (ext:env | inurl:".env.production" | inurl:".env.local" | inurl:".env.backup" | inurl:".env.bak" | inurl:".env~" | inurl:".env.old" | inurl:".env.dev" | inurl:".env.staging" | inurl:".env.test") (intext:"DB_PASSWORD" | intext:"SECRET_KEY" | intext:"API_KEY" | intext:"APP_SECRET" | intext:"AWS_ACCESS_KEY_ID" | intext:"JWT_SECRET" | intext:"REDIS_PASSWORD" | intext:"MONGODB_URI" | intext:"PRIVATE_KEY")'
      },
      {
        title: 'AWS / GCP / Azure Cloud Credentials',
        icon: '☁️',
        platforms: ['google'],
        query: 'site:{T} (ext:env | ext:yml | ext:json | ext:ini | ext:cfg | ext:conf) ("AKIA" | "aws_secret_access_key" | "AWS_SESSION_TOKEN" | "AZURE_CLIENT_SECRET" | "AZURE_STORAGE_KEY" | "AIzaSy" | "private_key_id" | "google_application_credentials")'
      },
      {
        title: 'Private Keys & Certificates Exposed',
        icon: '🔐',
        platforms: ['google'],
        query: 'site:{T} ("-----BEGIN RSA PRIVATE KEY-----" | "-----BEGIN OPENSSH PRIVATE KEY-----" | "-----BEGIN EC PRIVATE KEY-----" | "-----BEGIN PGP PRIVATE KEY BLOCK-----" | "-----BEGIN PRIVATE KEY-----" | ext:pem | ext:key "PRIVATE" | inurl:"/id_rsa" | inurl:"/server.key")'
      },
      {
        title: 'Service API Keys (Slack, Stripe, Twilio, SendGrid…)',
        icon: '🔑',
        platforms: ['google'],
        query: 'site:{T} ("xoxb-" | "xoxa-" | "xoxp-" | "sk_live_" | "rk_live_" | "TWILIO_AUTH_TOKEN" | "SG." "sendgrid" | "ghp_" | "ghs_" | "glpat-" | "OPENAI_API_KEY" | "sk-proj-" | "shopify_access_token" | "PAYPAL_SECRET" | "ALGOLIA_ADMIN_KEY" | "DISCORD_TOKEN" | "TELEGRAM_BOT_TOKEN" | "FIREBASE_SERVER_KEY")'
      },
      {
        title: 'Hardcoded Credentials in Source Code',
        icon: '👨‍💻',
        platforms: ['google'],
        query: 'site:{T} (ext:php | ext:py | ext:rb | ext:js | ext:java | ext:go | ext:ts) ("password =" | "passwd =" | "secret =" | "api_key =" | "Authorization: Bearer" | "x-api-key:" | "client_secret" | "access_token" | "auth_token")'
      },
      {
        title: 'Database Connection Strings',
        icon: '🗄️',
        platforms: ['google'],
        query: 'site:{T} ("jdbc:mysql://" | "jdbc:postgresql://" | "jdbc:sqlserver://" | "mongodb+srv://" "password" | "redis://:password@" | "mysql://root:" | "postgresql://postgres:" | "mssql://sa:" | "amqp://guest:")'
      },
      {
        title: 'Config Backups (wp-config, settings.py, web.config)',
        icon: '🧩',
        platforms: ['google'],
        query: 'site:{T} (inurl:"wp-config.php.bak" | inurl:"wp-config.php~" | inurl:"wp-config.php.old" | inurl:"settings.py" "SECRET_KEY" | inurl:"application.yml" "password" | inurl:"database.yml" | inurl:"config.php" "password" | inurl:"parameters.yml" "password" | inurl:"secrets.yml" | inurl:"credentials.json" | inurl:".htpasswd")'
      },
      {
        title: 'Pastebin / Gist Credential Leaks',
        icon: '📋',
        platforms: ['google'],
        query: 'site:pastebin.com "{T}" ("password" | "secret" | "api_key" | "BEGIN RSA PRIVATE KEY" | "DB_PASSWORD") | site:gist.github.com "{T}" ("password" | "secret" | "api_key" | "token") | site:paste.ee "{T}" | site:ghostbin.co "{T}"'
      },
      {
        title: 'PII Leaks (CSV / XLS / SQL dumps)',
        icon: '📊',
        platforms: ['google'],
        query: 'site:{T} (filetype:csv | filetype:xls | filetype:xlsx | filetype:sql | filetype:dump) ("email" "password" | "ssn" | "social_security" | "credit_card" | "card_number" | "INSERT INTO users" | "INSERT INTO accounts")'
      },
      {
        title: 'Slack Webhook / Internal Token Leaks',
        icon: '💬',
        platforms: ['google'],
        query: 'site:{T} ("hooks.slack.com/services" | "T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}" | "xoxp-" | "xoxb-" | "xoxa-" | "xoxs-") | site:github.com "{T}" "hooks.slack.com"'
      },
      {
        title: 'Firebase / NoSQL Exposed DB',
        icon: '🔥',
        platforms: ['google'],
        query: 'site:{T} (inurl:"firebaseio.com/.json" | inurl:".firebaseio.com" ".json" | inurl:"firebase.google.com" "database" | inurl:"/database.rules.json") | site:firebaseio.com "{T}"'
      },
      {
        title: 'Source Maps Exposed (.map files)',
        icon: '🗺️',
        platforms: ['google'],
        query: 'site:{T} (ext:js.map | ext:css.map | inurl:".min.js.map" | inurl:"main.chunk.js.map" | inurl:"bundle.js.map" | inurl:"app.js.map")'
      },
      {
        title: 'JWT / OAuth Secrets in Code',
        icon: '🪙',
        platforms: ['google'],
        query: 'site:{T} (ext:js | ext:ts | ext:py | ext:rb | ext:go) ("jwt_secret" | "JWT_SECRET" | "jwt.sign" | "HS256" | "RS256" | "client_secret" | "oauth_secret" | "token_secret" | "REFRESH_TOKEN_SECRET")'
      },
    ],

    /* ══════════════════════════════ HIGH ══════════════════════════════ */
    high: [
      {
        title: 'SQL Dumps & Database Backups',
        icon: '🗃️',
        platforms: ['google'],
        query: 'site:{T} (ext:sql | ext:dump | intitle:"index of" ".sql" | intitle:"index of" ".dump" | inurl:"/backup" intitle:"index of" | inurl:"/db_backup" | "backup" ext:zip "database" | inurl:"mysqldump" | inurl:"database.sql")'
      },
      {
        title: 'Admin & Management Panels',
        icon: '🛡️',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/admin" | inurl:"/administrator" | inurl:"/admin-panel" | inurl:"/manage" | inurl:"/wp-admin" | inurl:"/cpanel" | inurl:"/webmail" | inurl:"/plesk" | inurl:"/directadmin" | intitle:"phpMyAdmin" | inurl:"/adminer.php" | inurl:"/phpmyadmin" | intitle:"admin dashboard")'
      },
      {
        title: 'DevOps Panels (Jenkins, Kibana, Grafana, Portainer…)',
        icon: '👷',
        platforms: ['google'],
        query: 'site:{T} (intitle:"Jenkins" "Build History" | intitle:"Kibana" "Discover" | inurl:":3000" intitle:"Grafana" | inurl:":9200" "Elasticsearch" | intitle:"Portainer" | intitle:"Traefik" "Dashboard" | inurl:"/sonarqube" | inurl:"/zabbix" | inurl:"/nagios" | intitle:"Rancher" | intitle:"ArgoCD")'
      },
      {
        title: 'Exposed .git / .svn / Version Control',
        icon: '🔀',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/.git/HEAD" | inurl:"/.git/config" | intitle:"index of" "/.git" | inurl:"/.svn/entries" | intitle:"index of" ".svn" | inurl:"/.hg/hgrc" | inurl:"/CVS/Root" | inurl:"/.bzr/README")'
      },
      {
        title: 'Cloud Storage Misconfigs (S3, Azure Blob, GCS)',
        icon: '🪣',
        platforms: ['google'],
        query: 'site:s3.amazonaws.com "{T}" | site:blob.core.windows.net "{T}" | site:storage.googleapis.com "{T}" | site:digitaloceanspaces.com "{T}" | site:firebasestorage.googleapis.com "{T}" | site:*.s3.amazonaws.com | site:*.s3-website*.amazonaws.com "{T}"'
      },
      {
        title: 'phpinfo() & Server Status Pages',
        icon: '🖥️',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/server-status" "Apache Server" | inurl:"/server-info" | inurl:"/nginx_status" | ext:php intitle:"phpinfo()" | inurl:"info.php" intitle:"phpinfo" | inurl:"test.php" intitle:"phpinfo" | inurl:"phpinfo.php" | inurl:"php_info.php")'
      },
      {
        title: 'Kubernetes / Docker / Terraform Leaks',
        icon: '🐳',
        platforms: ['google'],
        query: 'site:{T} (inurl:"docker-compose.yml" | inurl:"docker-compose.yaml" | inurl:"Dockerfile" "password" | inurl:"kubernetes" ext:yml "password" | inurl:"terraform.tfvars" | inurl:".tfstate" | inurl:"ansible" ext:yml "ansible_password" | inurl:"Vagrantfile" "password")'
      },
      {
        title: 'Log Files with Credentials / Tokens',
        icon: '📜',
        platforms: ['google'],
        query: 'site:{T} (ext:log "password" | ext:log "Authorization:" | ext:log "Bearer " | ext:log "api_key" | ext:log "access_token" | intitle:"index of" "error.log" | intitle:"index of" "debug.log" | intitle:"index of" "access.log" | ext:log "PRIVATE KEY")'
      },
      {
        title: 'SSRF-Prone Parameters',
        icon: '🌊',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?url=" | inurl:"?uri=" | inurl:"?endpoint=" | inurl:"?webhook=" | inurl:"?dest=" | inurl:"?path=" | inurl:"?image_url=" | inurl:"?imageUrl=" | inurl:"?proxy=" | inurl:"?fetch=" | inurl:"?load=" | inurl:"?feed=" | inurl:"?source=" | inurl:"?link=" | inurl:"?host=")'
      },
      {
        title: 'File Upload Endpoints',
        icon: '📤',
        platforms: ['google'],
        query: 'site:{T} (inurl:"upload" | inurl:"file-upload" | inurl:"fileupload" | inurl:"uploadFile" | inurl:"upload.php" | inurl:"uploader" | intitle:"upload" | inurl:"import" | inurl:"attachments/upload" | inurl:"/api/upload")'
      },
      {
        title: 'Exposed .npmrc / .pypirc / Maven Tokens',
        icon: '📦',
        platforms: ['google'],
        query: 'site:{T} (inurl:".npmrc" "authToken" | inurl:".npmrc" "_auth" | inurl:".pypirc" "password" | inurl:".m2/settings.xml" "password" | inurl:"nuget.config" "apikey" | inurl:".gem/credentials" | inurl:"pip.conf" "index-url")'
      },
      {
        title: 'GraphQL Introspection Enabled',
        icon: '🔮',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/graphql" | inurl:"/graphiql" | inurl:"/playground" | inurl:"/api/graphql" | inurl:"/__graphql" | inurl:"/graphql/console" | intitle:"GraphQL Playground" | intitle:"GraphiQL")'
      },
      {
        title: 'Exposed Monitoring / Metrics Endpoints',
        icon: '📡',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/metrics" | inurl:"/prometheus" | inurl:"/actuator/prometheus" | inurl:"/stats" | inurl:"/__health" | inurl:"/_health" | inurl:"/healthz" | inurl:"/readyz" | inurl:"/live" | inurl:"/ready")'
      },
    ],

    /* ══════════════════════════════ MEDIUM ══════════════════════════════ */
    medium: [
      {
        title: 'SQL & Application Error Messages',
        icon: '❗',
        platforms: ['google'],
        query: 'site:{T} ("SQL syntax.*MySQL" | "ORA-[0-9]" | "SQLSTATE[" | "Warning: mysql_" | "Warning: pg_" | "Traceback (most recent call last)" | "Fatal error:" | "Uncaught exception" | "stack trace" | "NullPointerException" | "ActiveRecord::RecordNotFound" | "NoMethodError" | "ODBC SQL Server Driver")'
      },
      {
        title: 'Debug / Development Endpoints',
        icon: '🔍',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/debug" | inurl:"/_debugbar" | inurl:"/telescope" | intitle:"Whoops!" | intitle:"Symfony Exception" | inurl:"/_profiler" | inurl:"?debug=1" | inurl:"?env=dev" | inurl:"/staging" | inurl:"/dev/" | intitle:"Error 500")'
      },
      {
        title: 'API Docs (Swagger / OpenAPI / Redoc)',
        icon: '📋',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/swagger-ui" | inurl:"/swagger.json" | inurl:"/swagger.yaml" | inurl:"/api-docs" | inurl:"/openapi.json" | inurl:"/openapi.yaml" | inurl:"/redoc" | inurl:"/.well-known/openid-configuration" | inurl:"/v1/docs" | inurl:"/v2/docs" | inurl:"/v3/docs")'
      },
      {
        title: 'Open Redirect Parameters',
        icon: '↪️',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?redirect=" | inurl:"?url=" | inurl:"?return=" | inurl:"?next=" | inurl:"?redir=" | inurl:"?continue=" | inurl:"?target=" | inurl:"?goto=" | inurl:"?destination=" | inurl:"?callback=" | inurl:"?to=" | inurl:"?location=" | inurl:"?forward=")'
      },
      {
        title: 'SQLi / LFI Parameter Candidates',
        icon: '💉',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?id=" | inurl:"?page=" | inurl:"?file=" | inurl:"?include=" | inurl:"?path=" | inurl:"?view=" | inurl:"?cat=" | inurl:"?action=" | inurl:"?cmd=" | inurl:"?query=" | inurl:"?name=" | inurl:"?article=" | inurl:"?load=" | inurl:"?doc=" | inurl:"index.php?id=")'
      },
      {
        title: 'Backup & Temp Files (.bak, .old, .swp)',
        icon: '🕰️',
        platforms: ['google'],
        query: 'site:{T} (ext:bak | ext:old | ext:backup | ext:save | ext:swp | ext:orig | ext:tmp | ext:copy | intitle:"index of" ".bak" | intitle:"index of" ".old" | inurl:"~" ext:php | ext:inc "password")'
      },
      {
        title: 'Spring Boot Actuator Endpoints',
        icon: '🍃',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/actuator" | inurl:"/actuator/env" | inurl:"/actuator/health" | inurl:"/actuator/mappings" | inurl:"/actuator/beans" | inurl:"/actuator/configprops" | inurl:"/actuator/logfile" | inurl:"/actuator/threaddump" | inurl:"/actuator/heapdump")'
      },
      {
        title: 'IDOR Parameter Candidates',
        icon: '🔢',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?user_id=" | inurl:"?account_id=" | inurl:"?order_id=" | inurl:"?invoice_id=" | inurl:"?customer_id=" | inurl:"?ticket_id=" | inurl:"?report_id=" | inurl:"?profile_id=" | inurl:"?doc_id=" | inurl:"?file_id=" | inurl:"?uid=" | inurl:"?pid=")'
      },
      {
        title: 'XSS Reflection Parameter Candidates',
        icon: '✏️',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?search=" | inurl:"?q=" | inurl:"?query=" | inurl:"?s=" | inurl:"?keyword=" | inurl:"?message=" | inurl:"?comment=" | inurl:"?text=" | inurl:"?input=" | inurl:"?term=" | inurl:"?lang=") -filetype:pdf'
      },
      {
        title: 'SSTI / Template Injection Candidates',
        icon: '🧪',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?template=" | inurl:"?theme=" | inurl:"?view=" | inurl:"?layout=" | inurl:"?tpl=" | inurl:"?render=" | inurl:"?page=" ext:py | inurl:"?name=" ext:php | inurl:"?format=" | inurl:"?output=")'
      },
      {
        title: 'Exposed Tokens in JS Files',
        icon: '📄',
        platforms: ['google'],
        query: 'site:{T} (ext:js "api_key" | ext:js "apiKey" | ext:js "client_id" | ext:js "client_secret" | ext:js "access_token" | ext:js "auth_token" | ext:js "PRIVATE_KEY" | ext:js "s3.amazonaws.com" | ext:js "firebase" "apiKey")'
      },
      {
        title: 'XXE / XML Endpoints',
        icon: '📰',
        platforms: ['google'],
        query: 'site:{T} (inurl:"?xml=" | inurl:"/xmlrpc" | inurl:"/soap" | inurl:"?wsdl" | inurl:"/wsdl" | inurl:"/api.xml" | inurl:"content-type=application/xml" | intitle:"WSDL" | inurl:"/web.asmx" | inurl:"service.asmx")'
      },
      {
        title: 'HTTP Request Smuggling Candidates',
        icon: '🚚',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/transfer-encoding" | inurl:"/content-length" | inurl:"/chunked" | inurl:"/api/v" inurl:"proxy" | inurl:"/proxy" | inurl:"/gateway" | inurl:"/forward")'
      },
    ],

    /* ══════════════════════════════ LOW ══════════════════════════════ */
    low: [
      {
        title: 'Login & SSO Portals',
        icon: '🚪',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/login" | inurl:"/signin" | inurl:"/sign-in" | inurl:"/sso/" | inurl:"/saml/" | inurl:"/cas/login" | inurl:"/oauth/authorize" | inurl:"/openid" | inurl:"/auth" | inurl:"/account/login" | intitle:"sign in" | intitle:"log in")'
      },
      {
        title: 'Sensitive Documents (PDF, DOC, XLS)',
        icon: '📎',
        platforms: ['google'],
        query: 'site:{T} (filetype:pdf "confidential" | filetype:pdf "internal use only" | filetype:doc "confidential" | filetype:xls "password" | filetype:txt "password" "username" | filetype:pdf "not for distribution" | filetype:docx "internal")'
      },
      {
        title: 'Technology Version Disclosure',
        icon: 'ℹ️',
        platforms: ['google'],
        query: 'site:{T} ("Powered by WordPress" | "generator" "Drupal" | "generator" "Joomla" | "Magento" "version" | "Powered by vBulletin" | "X-Powered-By: PHP" | "X-Powered-By: ASP.NET" | "Powered by WooCommerce" | "Django" "version" | "Laravel" "debug")'
      },
      {
        title: 'Directory Listings',
        icon: '📂',
        platforms: ['google'],
        query: 'site:{T} (intitle:"index of" | intitle:"Index of /" | intitle:"Directory listing" | "parent directory" | intitle:"index of" "last modified" | intitle:"index of" "name" "size" "description")'
      },
      {
        title: 'robots.txt / sitemap / security.txt',
        icon: '🤖',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/robots.txt" | inurl:"/sitemap.xml" | inurl:"/sitemap_index.xml" | inurl:"/.well-known/security.txt" | inurl:"/humans.txt" | inurl:"/ads.txt" | inurl:"/app-ads.txt" | inurl:"/.well-known/change-password")'
      },
      {
        title: 'Collaboration & Internal Tools (Jira, Confluence, GitLab)',
        icon: '📌',
        platforms: ['google'],
        query: 'site:{T} (intitle:"Confluence" | intitle:"System Dashboard" "Jira" | intitle:"Sign in · GitLab" | inurl:"/owa/" intitle:"Outlook" | "SharePoint" "AllItems.aspx" | intitle:"Mattermost" | intitle:"Rocket.Chat" | inurl:"/wiki" intitle:"wiki" | intitle:"Notion")'
      },
      {
        title: 'Network Devices & IoT',
        icon: '📡',
        platforms: ['google'],
        query: 'site:{T} (intitle:"Network Camera" | intitle:"WebcamXP" | intitle:"RouterOS" "MikroTik" | intitle:"pfSense" | intitle:"Fortinet" | intitle:"SonicWall" | intitle:"Cisco" "login" | intitle:"Juniper" "login" | intitle:"Palo Alto" "login")'
      },
      {
        title: 'CORS / Cross-Origin Misconfiguration',
        icon: '🔄',
        platforms: ['google'],
        query: 'site:{T} (inurl:"/api/" | inurl:"/rest/" | inurl:"/v1/" | inurl:"/v2/" | inurl:"/v3/") ("Access-Control-Allow-Origin: *" | "Access-Control-Allow-Credentials: true")'
      },
    ],

    /* ══════════════════════════════ INFO / RECON ══════════════════════════════ */
    info: [
      {
        title: 'Subdomain Discovery (Google)',
        icon: '🌐',
        platforms: ['google'],
        query: 'site:*.{T} -www -mail -ftp -webmail -smtp -imap | site:*.*.{T}'
      },
      {
        title: 'Certificate Transparency (crt.sh)',
        icon: '📜',
        platforms: ['crtsh'],
        query: 'https://crt.sh/?q=%25.{T}&exclude=expired'
      },
      {
        title: 'crt.sh JSON API (All Certs)',
        icon: '🔏',
        platforms: ['crtsh'],
        query: 'https://crt.sh/?q=%25.{T}&output=json'
      },
      {
        title: 'Wayback Machine – All URLs',
        icon: '🏛️',
        platforms: ['wayback'],
        query: 'https://web.archive.org/cdx/search/cdx?url=*.{T}/*&output=text&fl=original&collapse=urlkey&limit=50000'
      },
      {
        title: 'Wayback – Sensitive File Types',
        icon: '📚',
        platforms: ['wayback'],
        query: 'https://web.archive.org/cdx/search/cdx?url=*.{T}/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar.gz|bak|7z|rar|log|env|secret|db|backup|yml|gz|config|csv|yaml|ini|key|pem|cert|asc|sh|bash_history|history|htpasswd|htaccess)'
      },
      {
        title: 'Wayback – JS Files',
        icon: '⚡',
        platforms: ['wayback'],
        query: 'https://web.archive.org/cdx/search/cdx?url=*.{T}/*&output=text&fl=original&filter=original:.*\\.js$&collapse=urlkey'
      },
      {
        title: 'Shodan – Hostname & Org',
        icon: '🛰️',
        platforms: ['shodan'],
        query: 'https://www.shodan.io/search?query=hostname%3A%22{T}%22'
      },
      {
        title: 'Shodan – SSL Cert Search',
        icon: '🔑',
        platforms: ['shodan'],
        query: 'https://www.shodan.io/search?query=ssl%3A%22{T}%22'
      },
      {
        title: 'Shodan – Open Ports & Services',
        icon: '🔓',
        platforms: ['shodan'],
        query: 'https://www.shodan.io/search?query=hostname%3A%22{T}%22+port%3A%228080%2C8443%2C9200%2C6379%2C27017%2C5601%2C3000%22'
      },
      {
        title: 'GitHub Code & Secret Leaks',
        icon: '🐙',
        platforms: ['github'],
        query: 'https://github.com/search?q=%22{T}%22+%28password+OR+secret+OR+api_key+OR+token+OR+BEGIN+PRIVATE+KEY+OR+AKIA%29&type=code'
      },
      {
        title: 'GitHub – Recent Commits',
        icon: '🔃',
        platforms: ['github'],
        query: 'https://github.com/search?q=%22{T}%22&type=commits&s=committer-date&o=desc'
      },
      {
        title: 'GitLab / Bitbucket / Sourcegraph Leaks',
        icon: '🦊',
        platforms: ['google'],
        query: 'site:gitlab.com "{T}" ("password" | "secret" | "token" | "BEGIN PRIVATE") | site:bitbucket.org "{T}" ("password" | "secret") | site:sourcegraph.com "{T}" ("password" | "api_key")'
      },
      {
        title: 'URLScan.io – Passive Recon',
        icon: '🔭',
        platforms: ['urlscan'],
        query: 'https://urlscan.io/search/#domain%3A{T}'
      },
      {
        title: 'URLScan – JS Files & Endpoints',
        icon: '🕵️',
        platforms: ['urlscan'],
        query: 'https://urlscan.io/search/#page.domain%3A{T}+AND+filename%3A*.js'
      },
      {
        title: 'GreyNoise – IP Intelligence',
        icon: '🌫️',
        platforms: ['grep'],
        query: 'https://viz.greynoise.io/query?gnql=classification%3Amalicious+ip%3A{T}'
      },
      {
        title: 'FOFA – Fingerprint & Ports',
        icon: '🌏',
        platforms: ['fofa'],
        query: 'https://fofa.info/result?qbase64=' + btoa('domain="{T}"')
      },
      {
        title: 'IntelligenceX – Paste & Breach Search',
        icon: '🕶️',
        platforms: ['intx'],
        query: 'https://intelx.io/?s={T}'
      },
      {
        title: 'Package Managers – Dependency Files',
        icon: '📦',
        platforms: ['google'],
        query: 'site:{T} (inurl:"package.json" | inurl:"composer.json" | inurl:"requirements.txt" | inurl:"Pipfile" | inurl:"go.mod" | inurl:"pom.xml" | inurl:"Gemfile" | inurl:"yarn.lock" | inurl:"package-lock.json")'
      },
      {
        title: 'HackerOne / Bugcrowd / Write-ups',
        icon: '🐞',
        platforms: ['google'],
        query: 'site:hackerone.com "{T}" | site:bugcrowd.com "{T}" | site:medium.com "{T}" "writeup" OR "bug bounty" | site:exploit-db.com "{T}" | site:cve.mitre.org "{T}" | site:nvd.nist.gov "{T}"'
      },
      {
        title: 'Email & Employee Discovery',
        icon: '📧',
        platforms: ['google'],
        query: 'site:{T} ("mailto:" "@{T}" | "@{T}" ext:txt | "contact" "@{T}" | filetype:pdf "@{T}" "email") | site:linkedin.com "{T}" "email" | site:hunter.io "{T}"'
      },
      {
        title: 'Cloud Asset Footprint',
        icon: '☁️',
        platforms: ['google'],
        query: 'site:{T} (inurl:".cloudfront.net" | inurl:".elb.amazonaws.com" | inurl:".azurewebsites.net" | inurl:".azurestaticapps.net" | inurl:".herokuapp.com" | inurl:".vercel.app" | inurl:".netlify.app" | inurl:".pages.dev" | inurl:".workers.dev" | inurl:".onrender.com")'
      },
      {
        title: 'Analytics / Tracking IDs (UA, GTM)',
        icon: '📈',
        platforms: ['google'],
        query: 'site:{T} ("UA-" "google-analytics" | "GTM-" | "G-" "googletagmanager" | "fbq(" "facebook" | "hotjar" | "mixpanel" | "segment.com" | "amplitude")'
      },
      {
        title: 'Censys.io – ASN & Cert Recon',
        icon: '🔬',
        platforms: ['censys'],
        query: 'https://search.censys.io/search?resource=hosts&q=dns.names%3A{T}'
      },
    ]
  };
