import nmap

def scan_network(subnet="192.168.0.0/24"):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-O -p 21,22,23,80,443,8080')

    devices = []
    for host in nm.all_hosts():
        device = {
            "ip": host,
            "mac": nm[host]['addresses'].get('mac', 'Unknown'),
            "vendor": nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown'),
            "open_ports": list(nm[host]['tcp'].keys()) if 'tcp' in nm[host] else [],
            "risks": [],
            "recommendations": []
        }

        # Risk analysis
        if 23 in device["open_ports"]:
            device["risks"].append("Telnet port open (insecure)")
            device["recommendations"].append("Disable Telnet or switch to SSH")

        if 80 in device["open_ports"]:
            device["risks"].append("Unsecured HTTP access")
            device["recommendations"].append("Use HTTPS where possible")

        devices.append(device)

    return devices
