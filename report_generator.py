from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def generate_report(devices, network_range):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')

    output = template.render(
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        network_range=network_range,
        devices=devices
    )

    with open("security_report.html", "w") as f:
        f.write(output)
    print("✅ Report generated: security_report.html")
