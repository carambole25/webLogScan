# webLogScan 🎯
A tool to analyze the Apache/Nginx server web log and detect potential intrusion attempts.

![graph](https://raw.githubusercontent.com/carambole25/webLogScan/refs/heads/main/graph_example.png)

SQLi, Xss, SSTI, LFI and RCE.

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
}
```

### Installation
```
git clone https://github.com/carambole25/webLogScan.git
cd webLogScan/
pip install -r requirements.txt
python3 wls.py
```

## Commande
```
usage: wls.py [-h] [-ss] [-is] [-bs] [-gg] path

Perform different types of scans.

positional arguments:
  path                Path to the file to scan

options:
  -h, --help          show this help message and exit
  -ss, --simple-scan  Retrieve the line containing suspicious characters and the potential attack type
  -is, --ip-scan      Retrieve suspicious IPs in a table
  -bs, --ban-scan     Use ufw to ban the suspicious IPs addresses
  -gg, --gen-graph    Generate graph from json data (path = json data location)

example : python3 wls.py -ss /var/log/apache2/log
```

If you want to save the output, simply do:
```
python3 wls.py -ss log > data.json
```


## To do
- [x] Add RCE detection
- [x] Make the code more clean
- [x] Save data in json format
- [x] Generate graph
- [ ] Make a docker implementation
