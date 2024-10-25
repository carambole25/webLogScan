# webLogScan 🎯
A tool to analyze the Apache/nginx server web log and detect potential intrusion attempts.

```
python3 wls.py -ss log 
{
    "0": {
        "date": "22/Oct/2024:08:15:32",
        "attack type": "SQLi",
        "ip": "192.168.0.12",
        "line": "192.168.0.12 - - [22/Oct/2024:08:15:32 +0000] \"GET /index.php?id=1' OR '1'='1 HTTP/1.1\" 200 532 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""
    },
    "1": {
        "date": "22/Oct/2024:09:45:14",
        "attack type": "XSS ",
        "ip": "203.0.113.5",
        "line": "203.0.113.5 - - [22/Oct/2024:09:45:14 +0000] \"GET /search.php?query=<script>alert('XSS')</script> HTTP/1.1\" 200 672 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64)\""
    },
    "2": {
        "date": "22/Oct/2024:10:55:19",
        "attack type": "SQLi",
        "ip": "203.0.113.12",
        "line": "203.0.113.12 - - [22/Oct/2024:10:55:19 +0000] \"GET /product/1' UNION SELECT username, password FROM users-- HTTP/1.1\" 200 856 \"-\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\""
    }
```

### Installation

If you don't want to install it you can use its docker version (see below)

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
  -ss, --simple-scan  Retrieve the line containing suspicious characters and the potential attack type
  -is, --ip-scan      Retrieve suspicious IPs in a table
  -bs, --ban-scan     Use ufw to ban suspicious IPs addresses

example : python3 wls.py -ss /var/log/apache2/log
```

### Docker implementation
```
docker run --rm carambole25/web-log-scan:latest
docker run --rm -v "$(pwd)/logpath/your_log_file:/logs/your_log_file" carambole25/web-log-scan:latest -ss /logs/your_log_file
docker run --rm -v "$(pwd)/logpath/your_log_file:/logs/your_log_file" carambole25/web-log-scan:latest -is /logs/your_log_file
docker run --rm --network host --privileged -v "$(pwd)/logpath/your_log_file:/logs/your_log_file" carambole25/web-log-scan:latest -bs /logs/your_log_file
```

## To do
- [x] Add RCE detection
- [x] Make the code more clean
- [x] Make a docker implementation
- [x] Save data in json format
