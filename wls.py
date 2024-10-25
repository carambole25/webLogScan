import sys
import argparse
from urllib.parse import unquote
import subprocess
import json

# Suspicious char
detection_rules = {
    "SQLi": ["'--", "UNION", "AND", "OR", "DROP", "TABLE"],
    "XSS ": ['<', '>', "alert", "iframe", "onerror"],
    "SSTI": ['{', '}', "7*7"],
    "LFI ": ["etc", "passwd", "..", "%00"],
    "RCE ": ['|', "wget", "curl", "$("]
} # I deliberately added a space to certain names (like xss or rce) to improve the display

def decode(line):
    # We decode twice to avoid bypasses by double encoding
    return unquote(unquote(line))

def get_content_of_log_file(LOG_PATH):
    return open(LOG_PATH, 'r').read()

def bad_content_detector(path):
    lines_with_bad_content = {}
    alert_number = 0

    content_log_file = get_content_of_log_file(path)
    content_log_file = decode(content_log_file)

    for line in content_log_file.splitlines():
        for attack_type, patterns in detection_rules.items():
            for p in patterns:
                if p in line:
                    ip = line.split()[0]
                    date = line.split()[3].replace("[", "")
                    lines_with_bad_content[alert_number] = {"date": date, "attack type": attack_type, "ip": ip, "line":line}
                    alert_number += 1
                    break
    return lines_with_bad_content

def simple_scan(path):
    suspect_lines = bad_content_detector(path)
    print(json.dumps(suspect_lines, indent=4))

def ip_scan(path):
    suspect_lines = bad_content_detector(path)
    ip_addresses = []
    for key, value in suspect_lines.items():
        ip_addresses.append(value.get("ip"))
    print(ip_addresses)

def ban_scan(path):
    ip_liste = ip_scan(path)
    rep = input("Are you sure you want to ban these IPs [Y/n] : ").lower()
    if rep == "yes" or rep == "y" or rep == "":
        subprocess.run(['ufw', 'enable'])
        for ip in ip_liste:
            subprocess.run(['ufw', 'deny', 'from', ip])
        subprocess.run(['ufw', 'reload'])
    
def ui(args):
    path = args.path
    if args.simple_scan:
        simple_scan(path)
    elif args.ip_scan:
        ip_scan(path)
    elif args.ban_scan:
        ban_scan(path)
    else:
        display_banner()

def main():
    parser = argparse.ArgumentParser(description="Perform different types of scans.")
    parser.add_argument("path", help="Path to the file to scan")
    parser.add_argument("-ss", "--simple-scan", action="store_true", help="Retrieve the line containing suspicious characters and the potential attack type")
    parser.add_argument("-is", "--ip-scan", action="store_true", help="Retrieve suspicious IPs in a table")
    parser.add_argument("-bs", "--ban-scan", action="store_true", help="Use ufw to ban the suspicious IPs addresses")

    args = parser.parse_args()
    ui(args)


if __name__ == '__main__':
    main()
