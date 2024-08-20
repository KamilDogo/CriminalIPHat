import requests
import json
import re
import os
import sys
from ipaddress import ip_address, ip_network
import optparse
from collections import defaultdict

def banner():
    print("  ______   _______   ______  __       __  ______  __    __   ______   __        ______  _______   __    __   ______  ________ ")
    print(" /      \\ |       \\ |      \\|  \\     /  \\|      \\|  \\  |  \\ /      \\ |  \\      |      \\|       \\ |  \\  |  \\ /      \\|        \\\\")
    print("|  $$$$$$\\| $$$$$$$\\ \\$$$$$$| $$\\   /  $$ \\$$$$$$| $$\\ | $$|  $$$$$$\\| $$       \\$$$$$$| $$$$$$$\\| $$  | $$|  $$$$$$\\\\$$$$$$$$")
    print("| $$   \\$$| $$__| $$  | $$  | $$$\\ /  $$$  | $$  | $$$\\| $$| $$__| $$| $$        | $$  | $$__/ $$| $$__| $$| $$__| $$  | $$   ")
    print("| $$      | $$    $$  | $$  | $$$$\\  $$$$  | $$  | $$$$\\ $$| $$    $$| $$        | $$  | $$    $$| $$    $$| $$    $$  | $$   ")
    print("| $$   __ | $$$$$$$\\  | $$  | $$\\$$ $$ $$  | $$  | $$\\$$ $$| $$$$$$$$| $$        | $$  | $$$$$$$ | $$$$$$$$| $$$$$$$$  | $$   ")
    print("| $$__/  \\| $$  | $$ _| $$_ | $$ \\$$$| $$ _| $$_ | $$ \\$$$$| $$  | $$| $$_____  _| $$_ | $$      | $$  | $$| $$  | $$  | $$   ")
    print(" \\$$    $$| $$  | $$|   $$ \\| $$  \\$ | $$|   $$ \\| $$  \\$$$| $$  | $$| $$     \\|   $$ \\| $$      | $$  | $$| $$  | $$  | $$   ")
    print("  \\$$$$$$  \\$$   \\$$ \\$$$$$$ \\$$      \\$$ \\$$$$$$ \\$$   \\$$ \\$$   \\$$ \\$$$$$$$$ \\$$$$$$ \\$$       \\$$   \\$$ \\$$   \\$$   \\$$   ")
    print("                                                                                                                              ")
    print("                                                                                                                              ")
    print("                                                                                                                              ")

def criminalip_asset_ip_report(ip, api_key, output_file=None):
    url = f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}"
    headers = {"x-api-key": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        try:
            result_data = response.json()
            if result_data.get("status") != 200:
                return None
            
            ip_info = result_data.get("ip", "N/A")
            whois_info = result_data.get("whois", {}).get("data", [])
            if whois_info:
                whois_info = whois_info[0]

            report = f"IP Address: {ip_info}\n\n"
            if whois_info:
                report += "WHOIS Information:\n"
                report += f"  AS Name: {whois_info.get('as_name', 'N/A')}\n"
                report += f"  AS Number: {whois_info.get('as_no', 'N/A')}\n"
                report += f"  Organization: {whois_info.get('org_name', 'N/A')}\n"
                report += f"  Organization Country Code: {whois_info.get('org_country_code', 'N/A')}\n"
                report += f"  Location: {whois_info.get('city', 'N/A')}, {whois_info.get('region', 'N/A')}\n"
                report += f"  Latitude, Longitude: {whois_info.get('latitude', 'N/A')}, {whois_info.get('longitude', 'N/A')}\n\n"

            port_dict = defaultdict(lambda: {"applications": set(), "vulnerabilities": defaultdict(dict)})

            open_ports = result_data.get("port", {}).get("data", [])
            for port_info in open_ports:
                port_no = port_info.get('open_port_no', 'N/A')
                application = f"{port_info.get('app_name', 'N/A')} {port_info.get('app_version', 'N/A')}"
                port_dict[port_no]["applications"].add(application)
                port_dict[port_no]["protocol"] = port_info.get('protocol', 'N/A')

            vulnerabilities = result_data.get("vulnerability", {}).get("data", [])
            for vuln in vulnerabilities:
                cve_id = vuln.get('cve_id', 'N/A')
                cvssv3_score = vuln.get('cvssv3_score', 'N/A')
                app_name = vuln.get('app_name', 'N/A')
                app_version = vuln.get('app_version', 'N/A')
                cwe_list = [cwe.get('cwe_name', '') for cwe in vuln.get('list_cwe', []) if cwe.get('cwe_name', '')]
                affected_ports = vuln.get('open_port_no_list', {}).get('TCP', [])

                for port in affected_ports:
                    if cve_id not in port_dict[port]["vulnerabilities"]:
                        port_dict[port]["vulnerabilities"][cve_id] = {
                            "cvssv3_score": cvssv3_score,
                            "app_name": app_name,
                            "app_version": app_version,
                            "cwes": cwe_list
                        }

            report += "Open Ports:\n"
            for port, details in port_dict.items():
                report += f"  Port: {port}\n"
                report += f"    Applications: {', '.join(details['applications'])}\n"
                report += f"    Protocol: {details['protocol']}\n"
                
                report += "\n"

                if details["vulnerabilities"]:
                    report += "    Vulnerabilities:\n"
                    for cve_id, vuln_details in details["vulnerabilities"].items():
                        report += f"      CVE ID: {cve_id}\n"
                        report += f"        CVSSv3 Score: {vuln_details['cvssv3_score']}\n"
                        report += f"        Application: {vuln_details['app_name']} {vuln_details['app_version']}\n"
                        if vuln_details['cwes']:
                            report += f"        CWE: {', '.join(vuln_details['cwes'])}\n"
                        report += "\n"

            if output_file:
                with open(output_file, 'a') as f:
                    f.write(report + "\n")
            else:
                print(report)

            return result_data
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[ERROR] {e}")
            return None
    else:
        print(f"[ERROR] HTTP {response.status_code}")
        return None

def is_internal_ip(ip):
    private_networks = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
        ip_network("::1/128"),
        ip_network("fc00::/7"),
        ip_network("fe80::/10"),
    ]
    ip_obj = ip_address(ip)
    return any(ip_obj in net for net in private_networks)

def is_valid_api_key(api_key):
    pattern = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{60}$")
    return bool(pattern.match(api_key))

def ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="info about one host", default="")
    parser.add_option("-l", "--list", dest="list", help="info about a list of hosts", default="")
    parser.add_option("--setkey", dest="setkey", help="set your api key automatically", default="")
    parser.add_option("-r", "--range", dest="range", help="scan a range of ips. ex: 192.168.1.1-192.168.1.255", default="")
    parser.add_option("-o", "--output", dest="output", help="specify an output file", default="")
    options, args = parser.parse_args()

    banner()

    if options.setkey:
        with open("api_key.txt", 'w') as f:
            f.write(options.setkey)
        api_key = options.setkey
    elif os.path.exists("api_key.txt"):
        with open("api_key.txt", 'r') as f:
            api_key = f.read().strip()
    else:
        print("API key not set. Use --setkey to set it.")
        sys.exit()

    if not is_valid_api_key(api_key):
        print("Invalid API key.")
        sys.exit()

    if options.ip:
        if not is_internal_ip(options.ip):
            criminalip_asset_ip_report(options.ip, api_key, options.output)
        else:
            print("Internal IP address detected. Skipping.")

    if options.list:
        with open(options.list, 'r') as file:
            for line in file:
                ip = line.strip()
                if not is_internal_ip(ip):
                    criminalip_asset_ip_report(ip, api_key, options.output)
                else:
                    print(f"Internal IP address detected ({ip}). Skipping.")

    if options.range:
        start_ip, end_ip = options.range.split('-')
        ip_list = ip_range(start_ip, end_ip)
        for ip in ip_list:
            if not is_internal_ip(ip):
                criminalip_asset_ip_report(ip, api_key, options.output)
            else:
                print(f"Internal IP address detected ({ip}). Skipping.")
