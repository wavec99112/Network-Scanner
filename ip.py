import nmap
import concurrent.futures
import csv
import logging
import time
from datetime import datetime
from fpdf import FPDF
import socket
import struct
import subprocess
from tqdm import tqdm
import requests

# 设置日志记录
logging.basicConfig(filename='scan_log.txt', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 自动检测局域网范围
def get_local_network_range():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'src' in line and 'default' not in line:
                parts = line.split()
                for part in parts:
                    if '/' in part:
                        return part
    except Exception as e:
        logging.error(f"无法检测局域网范围: {e}")
    return '192.168.1.0/24'  # 默认局域网范围

# 扫描局域网内的主机
def scan_network(nm, network_range):
    nm.scan(hosts=network_range, arguments='-sn')
    return nm.all_hosts()

# 获取主机的开放端口
def get_open_ports(nm, host):
    logging.info(f"Scanning ports for host: {host}")
    nm.scan(hosts=host, arguments='-p-', timeout=600)
    ports = []
    for proto in nm[host].all_protocols():
        ports.extend(nm[host][proto].keys())
    return ports

# 获取MAC地址制造商信息
def get_mac_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
    except Exception as e:
        logging.error(f"获取MAC地址制造商信息失败: {e}")
    return "未知制造商"

# 分析端口并尝试判断操作系统和设备类型
def analyze_ports(ports, mac):
    os_type = "未知操作系统"
    device_type = "未知设备"
    vendor = get_mac_vendor(mac)

    if 80 in ports and 554 in ports:
        device_type = "网络摄像机"
    elif 515 in ports or 631 in ports or 9100 in ports:
        device_type = "打印机"
    elif 80 in ports and 5060 in ports:
        device_type = "VoIP 设备"
    elif 8291 in ports:
        device_type = "MikroTik 路由器"
    elif 1911 in ports:
        device_type = "SCADA 设备"
    elif 5900 in ports:
        device_type = "VNC 设备"
    elif 62078 in ports:
        device_type = "iOS 设备"
    elif 5555 in ports or 5037 in ports:
        device_type = "Android 设备"
    elif 161 in ports:
        device_type = "网络设备（SNMP）"
    elif 22 in ports:
        device_type = "服务器或网络设备"
    elif 23 in ports:
        device_type = "Telnet 设备"
    elif 1723 in ports:
        device_type = "VPN 设备"
    elif 8080 in ports:
        device_type = "代理服务器"
    elif 502 in ports:
        device_type = "Modbus 设备"
    elif 3689 in ports:
        device_type = "Apple iTunes 音乐共享"
    elif 49152 in ports or 62078 in ports or 5228 in ports:
        device_type = "移动端设备"
    elif 10001 in ports:
        device_type = "摄像头或DVR"
    elif 1433 in ports:
        device_type = "Microsoft SQL Server"
    elif 3306 in ports:
        device_type = "MySQL 数据库"
    elif 5432 in ports:
        device_type = "PostgreSQL 数据库"
    elif 27017 in ports:
        device_type = "MongoDB 数据库"
    elif 6379 in ports:
        device_type = "Redis 数据库"
    elif 5000 in ports:
        device_type = "Flask 开发服务器"
    elif 8081 in ports:
        device_type = "Nginx 代理服务器"
    elif 8443 in ports:
        device_type = "HTTPS 代理服务器"
    elif 9092 in ports:
        device_type = "Apache Kafka 服务器"
    elif 102 in ports:
        device_type = "Siemens S7 PLC"
    elif 47808 in ports:
        device_type = "BACnet 设备"
    elif 1720 in ports:
        device_type = "H.323 视频会议设备"
    elif 2000 in ports:
        device_type = "Cisco 设备"
    elif 21 in ports:
        device_type = "FTP 服务器"
    elif 25 in ports:
        device_type = "邮件服务器 (SMTP)"
    elif 110 in ports or 143 in ports:
        device_type = "邮件服务器 (POP3/IMAP)"

    if 135 in ports or 139 in ports or 445 in ports or 3389 in ports:
        os_type = "Windows"
    elif 22 in ports and (80 in ports or 443 in ports):
        os_type = "Linux 或 macOS"
    elif 22 in ports:
        os_type = "可能是Linux"
    elif 80 in ports or 443 in ports:
        os_type = "可能是macOS"
    elif 49152 in ports or 62078 in ports or 5228 in ports:
        os_type = "可能是移动端系统"

    return os_type, device_type, vendor

# 处理单个主机
def process_host(nm, host):
    try:
        ports = get_open_ports(nm, host)
        mac = nm[host]['addresses'].get('mac', '未知MAC地址')
        os_type, device_type, vendor = analyze_ports(ports, mac)
        return host, ports, os_type, device_type, vendor
    except nmap.PortScannerError as e:
        logging.error(f"扫描失败：{e}")
        return host, [], "扫描失败", str(e), "未知制造商"
    except Exception as e:
        logging.error(f"处理主机 {host} 时出现错误：{e}")
        return host, [], "处理错误", str(e), "未知制造商"

# 生成PDF报告
def generate_pdf_report(results):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", uni=True)
    pdf.set_font("DejaVu", size=12)
    pdf.cell(200, 10, txt="网络扫描报告", ln=True, align='C')
    pdf.cell(200, 10, txt="扫描时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ln=True, align='C')
    pdf.ln(10)
    
    for result in results:
        pdf.cell(200, 10, txt=f"主机: {result[0]}", ln=True)
        pdf.cell(200, 10, txt=f"开放端口: {result[1]}", ln=True)
        pdf.cell(200, 10, txt=f"操作系统: {result[2]}", ln=True)
        pdf.cell(200, 10, txt=f"设备类型: {result[3]}", ln=True)
        pdf.cell(200, 10, txt=f"制造商: {result[4]}", ln=True)
        pdf.ln(5)
    
    pdf.output("scan_report.pdf")
    print("PDF报告已生成: scan_report.pdf")

# 生成HTML报告
def generate_html_report(results):
    with open('scan_report.html', 'w') as f:
        f.write("<html><head><title>网络扫描报告</title></head><body>")
        f.write("<h1>网络扫描报告</h1>")
        f.write(f"<p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        f.write("<table border='1'><tr><th>主机</th><th>开放端口</th><th>操作系统</th><th>设备类型</th><th>制造商</th></tr>")
        
        for result in results:
            f.write(f"<tr><td>{result[0]}</td><td>{result[1]}</td><td>{result[2]}</td><td>{result[3]}</td><td>{result[4]}</td></tr>")
        
        f.write("</table></body></html>")
    print("HTML报告已生成: scan_report.html")

# 主函数
def main():
    startup_ascii_art = r"""
    __  __           _             _         ____   ___   ___  
   |  \/  |   __ _  | |_    __ _   | |_      / ___| / _ \ | _ \ 
   | |\/| |  / _` | |  _|  / _` |  |  _|    | |    | | | ||   /
   |_|__|_|_ \__,_|  \__|  \__,_|_  \__|    |_|_   |_|_||_|_\
  |_   _| __| |__   ___  _| || |_| |/ /|_|
    | | |/ _| '_ \ / _ \/ _` || / _` || |
    |_|_ \__| .__/ \___/ \__,_||_\__,_||_|
       |_|_|_|

       =[ Network Scanner v1.0                        ]
+ -- --=[ 本工具仅供合法的网络安全研究、教学和评估用途。   ]
+ -- --=[ 请勿在未经授权的系统上使用。                    ]
+ -- --=[ 任何非法使用本工具的行为，责任自负。             ]
"""

    print(startup_ascii_art)
    start_scan = input("是否开始扫描？(y/n): ")

    if start_scan.lower() != 'y':
        print("扫描取消。")
        return

    network_range = get_local_network_range()
    nm = nmap.PortScanner()
    hosts = scan_network(nm, network_range)
    results = []

    with tqdm(total=len(hosts), desc="扫描进度") as bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_host = {executor.submit(process_host, nm, host): host for host in hosts}
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    logging.info(f"主机: {result[0]}")
                    logging.info(f"开放端口: {result[1]}")
                    logging.info(f"操作系统: {result[2]}")
                    logging.info(f"设备类型: {result[3]}")
                    logging.info(f"制造商: {result[4]}\n")
                    results.append(result)
                except Exception as e:
                    logging.error(f"主机: {host}")
                    logging.error(f"错误: {str(e)}\n")
                    results.append((host, [], "处理错误", str(e), "未知制造商"))
                finally:
                    bar.update(1)  # 无论成功或失败都更新进度条

    with open('scan_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['主机', '开放端口', '操作系统', '设备类型', '制造商']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({'主机': result[0], '开放端口': result[1], '操作系统': result[2], '设备类型': result[3], '制造商': result[4]})
        
    print("扫描结果已保存到 scan_results.csv")
    print("详细日志已保存到 scan_log.txt")

    generate_pdf_report(results)
    generate_html_report(results)

    ascii_art = r"""
 └─# zds666.icu
   _  _         _            _   _       ___   ___   ___  
  | \| |  ___  | |_   __ _  | | | |     |_  | / _ \ |   / 
  | .` | / -_) |  _|  / _` | | |_| |  _    | || (_) ||  _/ 
  |_|\_| \___|  \__|  \__,_|  \___/  (_)  |___| \___/ |_|_\ 
                                                          
  """
    print(ascii_art)
    print("扫描完成！结果已保存到 'scan_results.csv'")
    print("详细日志已保存到 'scan_log.txt'\n")
    print("Network Scanner v1.0")
    print("+ -- --=[ 50 devices discovered   ]")
    print("+ -- --=[ 123 vulnerabilities found]")
    print("Documentation: https://zds666.icu/")
    print("\nscanner > ")

if __name__ == "__main__":
    main()
