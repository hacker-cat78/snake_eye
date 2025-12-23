import socket
import sys

# ====== 服务探测 ======
def detect_service(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # HTTP 主动请求
        if port in (80, 8080, 8000, 443):
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except:
        return None


# ====== Banner 分析 ======
def analyze_banner(banner):
    service = "Unknown"
    os_info = "Unknown"

    if not banner:
        return service, os_info

    b = banner.lower()

    # 服务判断
    if "ssh" in b:
        service = "SSH"
    elif "http" in b:
        service = "HTTP"
    elif "mysql" in b:
        service = "MySQL"
    elif "redis" in b:
        service = "Redis"
    elif "ftp" in b:
        service = "FTP"

    # 系统判断
    if "ubuntu" in b:
        os_info = "Linux (Ubuntu)"
    elif "debian" in b:
        os_info = "Linux (Debian)"
    elif "centos" in b:
        os_info = "Linux (CentOS)"
    elif "windows" in b or "microsoft" in b:
        os_info = "Windows"

    return service, os_info


# ====== 端口扫描 ======
def scan_ports(ip, ports):
    print(f"\n[*] 开始扫描 {ip}\n")

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                banner = detect_service(ip, port)
                service, os_info = analyze_banner(banner)

                print(f"[+] {port}/tcp OPEN")
                print(f"    Service : {service}")
                print(f"    OS      : {os_info}")
                if banner:
                    print(f"    Banner  : {banner[:80]}")
                print()

        except:
            pass


# ====== 主入口 ======
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python scanner.py <IP或域名>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        ip = socket.gethostbyname(target)
    except:
        print("无法解析目标")
        sys.exit(1)

    ports = [21, 22, 23, 80, 443, 3306, 6379, 8080]
    scan_ports(ip, ports)
