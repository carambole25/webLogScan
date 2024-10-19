import sys
from urllib.parse import unquote
import subprocess


SQLi_car = ["'", "--", "UNION", "AND", "OR", "DROP", "TABLE"]
XSS_car = ["<", ">", "alert", "iframe"]
SSTI_car = ['{', '}', '7*7']
LFI_car = ['etc', 'passwd', '..']


def decode(line):
    # On decode deux fois pour éviter les bypass par doubles encodages
    return unquote(unquote(line))

def get_content(LOG_PATH):
    file = open(LOG_PATH, 'r')
    return file.read()

def bad_content_detector(content_log_file):
    lines_with_bad_content = {}
    for line in content_log_file.splitlines():
        line = decode(line)
        for car in SQLi_car:
            if car in line:
                lines_with_bad_content[line] = "SQLi"
        for car in XSS_car:
            if car in line:
                lines_with_bad_content[line] = "Xss"
        for car in SSTI_car:
            if car in line:
                lines_with_bad_content[line] = "SSTI"
        for car in LFI_car:
            if car in line:
                lines_with_bad_content[line] = "LFI"
    return lines_with_bad_content

def simple_scan(path):
    content_log = get_content(path)
    suspect_lines = bad_content_detector(content_log)
    for cle, valeur in suspect_lines.items():
        print(valeur, " | ", cle)

def ip_scan(path):
    content_log = get_content(path)
    suspect_lines = bad_content_detector(content_log)
    ip = list(set([i.split()[0] for i in suspect_lines]))
    print(ip)

def ban_scan(path):
    content_log = get_content(path)
    suspect_lines = bad_content_detector(content_log)
    ip_liste = list(set([i.split()[0] for i in suspect_lines]))

    subprocess.run(['ufw', 'enable'])
    for ip in ip_liste:
        subprocess.run(['ufw', 'deny', 'from', ip])
    subprocess.run(['ufw', 'reload'])

def display_banner():
    print("WLS - webLogScan")
    print("by Carambole https://github.com/MrCarambole")
    print("-"*50)
    display_help()

def display_help():
    print("""Usage : python3 wls.py <arg> <path>
          -ss simple scan : retrieve suspicious lines
          -is ip scan : recover only the IPs responsible for suspicious requests
          -bs ban scan : ban IPs that made suspicious requests
          example : python3 wls.py -ss /var/log/apache2/log""")

def ui(argv):
        path = argv[-1]
        if "-ss" in argv:
            simple_scan(path)
        elif "-is" in argv:
            ip_scan(path)
        elif "-bs" in argv:
            ban_scan(path)
        else:
            display_banner()

def main():
    ui(sys.argv)

if __name__ == '__main__':
    main()
