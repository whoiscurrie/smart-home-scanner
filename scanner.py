import nmap
import requests

def scan_network(subnet="192.168.0.0/24"):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-O -sV -p 21,22,23,80,443,8080')

    devices = []

    for host in nm.all_hosts():
        device = {
            "ip": host,
            "mac": nm[host]['addresses'].get('mac', 'Unknown'),
            "vendor": nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown'),
            "open_ports": [],
            "services": [],
            "risks": [],
            "recommendations": []
        }

        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                service_info = nm[host]['tcp'][port]
                product = service_info.get('product', 'Unknown')
                version = service_info.get('version', 'Unknown')
                name = service_info.get('name', 'Unknown')

                device["open_ports"].append(port)
                device["services"].append({
                    "port": port,
                    "name": name,
                    "product": product,
                    "version": version
                })

                # Basic risk logic
                if port == 23:
                    device["risks"].append("Telnet port open (insecure)")
                    device["recommendations"].append("Disable Telnet or switch to SSH")

                if port == 80 and product.lower() != "https":
                    device["risks"].append("Unsecured HTTP access")
                    device["recommendations"].append("Use HTTPS where possible")

                # CVE lookup
                if product != "Unknown" and version != "Unknown":
                    cves = lookup_cves(product, version)
                    for cve in cves[:3]:  # Limit to top 3
                        device["risks"].append(f"{cve['id']}: {cve['summary']}")
                        device["recommendations"].append("Check for patches or updates")

        devices.append(device)

    return devices

def lookup_cves(product, version):
    query = f"{product} {version}"
    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{query}")
        if response.ok:
            return response.json().get('results', [])
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
    return []
