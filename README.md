# webLogScan 🎯
A tool to analyze the Apache/nginx server web log and detect potential intrusion attempts.

```
python3 wls.py -ss log 
SQLi  |  192.168.0.12 - - [21/Oct/2024:10:23:45 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 200 532 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
XSS   |  203.0.113.5 - - [21/Oct/2024:10:25:12 +0000] "GET /search.php?query=<script>alert('XSS')</script> HTTP/1.1" 200 672 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"
SQLi  |  203.0.113.12 - - [21/Oct/2024:10:27:45 +0000] "GET /product/1' UNION SELECT username, password FROM users-- HTTP/1.1" 200 856 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
RCE   |  192.168.0.15 - - [21/Oct/2024:10:29:03 +0000] "GET /home?name={{7*7}} HTTP/1.1" 200 925 "-" "curl/7.64.1"
LFI   |  198.51.100.2 - - [21/Oct/2024:10:30:27 +0000] "GET /etc/passwd HTTP/1.1" 403 138 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0)"
LFI   |  203.0.113.17 - - [21/Oct/2024:10:31:48 +0000] "GET /page.php?file=../../../../etc/passwd HTTP/1.1" 200 1240 "-" "Mozilla/5.0 (X11; Linux x86_64)"
XSS   |  198.51.100.33 - - [21/Oct/2024:10:33:06 +0000] "GET /login.php?username=admin&password=<script>alert('XSS')</script> HTTP/1.1" 403 523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SQLi  |  192.168.0.25 - - [21/Oct/2024:10:35:59 +0000] "GET /product.php?id=1; DROP TABLE users;-- HTTP/1.1" 200 456 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
RCE   |  192.168.0.11 - - [21/Oct/2024:10:39:14 +0000] "GET /fonction?exec=toto | curl google.fr HTTP/1.1" 200 2789 "-" "Mozilla/5.0 (Linux; Android 11)"
```

### Installation
```
git clone https://github.com/carambole25/webLogScan.git
```

Tester l'installation :
```
cd webLogScan/
python3 wls.py
```

## Commande
```
usage: wls.py [-h] [-ss] [-is] [-bs] path

positional arguments:
  path                Path to the file to scan

options:
  -h, --help          show this help message and exit
  -ss, --simple-scan  Perform a simple scan
  -is, --ip-scan      Perform an IP scan
  -bs, --ban-scan     Perform a ban scan

example : python3 wls.py -ss /var/log/apache2/log
```

## To do
- [x] Add RCE detection
- [x] Make the code more clean 
- [ ] Save data in json format
