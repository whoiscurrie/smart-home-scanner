from scanner import scan_network
from report_generator import generate_report

def main():
    print("🔍 Smart Home Network Security Audit Tool")
    subnet = input("Enter your subnet (default 192.168.0.0/24): ") or "192.168.0.0/24"
    print(f"Scanning network: {subnet}...")

    devices = scan_network(subnet)
    print(f"Found {len(devices)} devices.")

    generate_report(devices, subnet)

if __name__ == "__main__":
    main()
