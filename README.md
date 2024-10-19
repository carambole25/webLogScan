# webLogScan 🎯
A tool to analyze the Apache/nginx server web log and detect potential intrusion attempts.

```
python3 wls.py -ss log
SQLi  |  203.0.113.5 - - [11/Oct/2024:14:32:10 +0200] "GET /product?id=1;DROP TABLE users HTTP/1.1" 500 234
Xss  |  198.51.100.9 - - [11/Oct/2024:14:32:13 +0200] "GET /search?q=<script>alert('XSS')</script> HTTP/1.1" 400 345
SSTI  |  198.51.100.9 - - [11/Oct/2024:14:32:21 +0200] "GET /api/item?id={{7*7}} HTTP/1.1" 500 1024
SQLi  |  198.51.100.9 - - [11/Oct/2024:14:32:30 +0200] "GET /product?id=5 UNION SELECT password FROM users HTTP/1.1" 500 654        
Xss  |  203.0.113.5 - - [11/Oct/2024:14:32:33 +0200] "GET /account/settings.php?user=<script>alert('XSS')</script> HTTP/1.1" 400 345
SSTI  |  198.51.100.9 - - [11/Oct/2024:14:32:39 +0200] "GET /template?value={{config}} HTTP/1.1" 500 1024
Xss  |  203.0.113.5 - - [11/Oct/2024:14:32:41 +0200] "GET /?q=<img src=javascript:alert('XSS')> HTTP/1.1" 400 234
SQLi  |  198.51.100.9 - - [11/Oct/2024:14:32:49 +0200] "GET /product?id=2 AND 1=1 HTTP/1.1" 500 234
Xss  |  203.0.113.5 - - [11/Oct/2024:14:32:52 +0200] "GET /search?q=<iframe src=javascript:alert('XSS')> HTTP/1.1" 400 345
LFI  |  192.168.1.85 - - [11/Oct/2024:14:32:01 +0200] "GET /etc/passwd HTTP/1.1" 200 2326
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
-ss simple scan : retrieve suspicious lines
-is ip scan : recover only the IPs responsible for suspicious requests
-bs ban scan : ban IPs that made suspicious requests

example : python3 wls.py -ss /var/log/apache2/log
```

## To do
- Add automatic ban functionalities linked to fail2ban
- Post request analysiser
- Save data in json format
