"""信息网络模块 - 网络配置、子网计算、DNS/DHCP、网络诊断、故障排除"""
import ipaddress
import re


# ============ 子网计算器 ============

def subnet_calculator(ip_cidr: str) -> dict:
    """子网计算器 - 输入CIDR格式如 192.168.1.0/24"""
    try:
        network = ipaddress.ip_network(ip_cidr, strict=False)
        hosts = list(network.hosts())
        return {
            "success": True,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "prefix_len": network.prefixlen,
            "host_count": network.num_addresses - 2 if network.num_addresses > 2 else 0,
            "first_host": str(hosts[0]) if hosts else "N/A",
            "last_host": str(hosts[-1]) if hosts else "N/A",
            "ip_range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
            "wildcard_mask": str(network.hostmask),
            "ip_class": _get_ip_class(int(network.network_address)),
            "is_private": network.is_private,
        }
    except ValueError as e:
        return {"success": False, "error": f"无效的CIDR格式: {e}"}


def _get_ip_class(ip_int: int) -> str:
    """判断IP地址类别"""
    first_octet = (ip_int >> 24) & 0xFF
    if first_octet < 128:
        return "A类"
    elif first_octet < 192:
        return "B类"
    elif first_octet < 224:
        return "C类"
    elif first_octet < 240:
        return "D类(组播)"
    else:
        return "E类(保留)"


def subnet_split(ip_cidr: str, new_prefix: int) -> dict:
    """子网划分 - 将一个网络划分为多个子网"""
    try:
        network = ipaddress.ip_network(ip_cidr, strict=False)
        if new_prefix <= network.prefixlen:
            return {"success": False, "error": f"新前缀长度必须大于{network.prefixlen}"}
        if new_prefix > 30:
            return {"success": False, "error": "前缀长度不能超过30（至少需要2个可用主机地址）"}

        subnets = list(network.subnets(new_prefix=new_prefix))
        result = []
        for i, subnet in enumerate(subnets):
            hosts = list(subnet.hosts())
            result.append({
                "index": i + 1,
                "network": str(subnet.network_address),
                "broadcast": str(subnet.broadcast_address),
                "range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A",
                "host_count": len(hosts),
                "cidr": str(subnet),
            })

        return {
            "success": True,
            "original": str(network),
            "new_prefix": new_prefix,
            "subnet_count": len(subnets),
            "subnets": result[:64],  # 限制输出数量
        }
    except ValueError as e:
        return {"success": False, "error": str(e)}


def ip_info(ip: str) -> dict:
    """查询IP地址信息"""
    try:
        addr = ipaddress.ip_address(ip)
        is_private = addr.is_private
        is_loopback = addr.is_loopback
        is_multicast = addr.is_multicast
        version = addr.version

        # 判断所属网段
        networks = []
        for prefix in [8, 16, 24]:
            try:
                net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                networks.append(str(net))
            except ValueError:
                pass

        return {
            "success": True,
            "ip": str(addr),
            "version": f"IPv{version}",
            "is_private": is_private,
            "is_loopback": is_loopback,
            "is_multicast": is_multicast,
            "binary": bin(int(addr)),
            "hex": hex(int(addr)),
            "networks": networks,
            "type": "私有地址" if is_private else ("回环地址" if is_loopback else ("组播地址" if is_multicast else "公网地址")),
        }
    except ValueError as e:
        return {"success": False, "error": f"无效的IP地址: {e}"}


# ============ 网络配置命令 ============

def network_config(action: str, config: dict = None) -> dict:
    """网络配置命令生成"""
    config = config or {}
    connection = config.get("connection", "ens33")
    ip = config.get("ip", "192.168.1.100")
    mask = config.get("mask", "24")
    gateway = config.get("gateway", "192.168.1.1")
    dns = config.get("dns", "8.8.8.8")
    dns2 = config.get("dns2", "8.8.4.4")
    hostname = config.get("hostname", "server01")
    network = config.get("network", "10.0.0.0/24")
    route_gw = config.get("route_gateway", "192.168.1.1")

    actions = {
        "show": {
            "name": "查看网络配置",
            "commands": [
                "ip addr show",
                "echo '---路由表---'",
                "ip route show",
                "echo '---DNS配置---'",
                "cat /etc/resolv.conf",
                "echo '---主机名---'",
                "hostnamectl",
                "echo '---网络连接---'",
                "nmcli con show",
                "echo '---监听端口---'",
                "ss -tlnp",
            ],
        },
        "static-ip": {
            "name": "配置静态IP地址",
            "commands": [
                f"nmcli con mod {connection} ipv4.addresses {ip}/{mask}",
                f"nmcli con mod {connection} ipv4.gateway {gateway}",
                f"nmcli con mod {connection} ipv4.dns {dns}",
                f"nmcli con mod {connection} ipv4.dns-search ''",
                f"nmcli con mod {connection} ipv4.method manual",
                f"nmcli con up {connection}",
                "ip addr show {connection}",
            ],
            "tips": [
                "先用 nmcli con show 查看连接名",
                "connection 名称通常是网卡名或连接名",
                "修改后需 nmcli con up 生效",
                "可用 ip addr show 验证配置",
            ],
        },
        "dhcp": {
            "name": "配置DHCP自动获取IP",
            "commands": [
                f"nmcli con mod {connection} ipv4.method auto",
                f"nmcli con mod {connection} ipv4.addresses ''",
                f"nmcli con mod {connection} ipv4.gateway ''",
                f"nmcli con up {connection}",
                "ip addr show",
                "dhclient -v {connection}",
            ],
            "tips": ["DHCP会自动获取IP、网关、DNS", "用 dhclient -v 可查看DHCP获取过程"],
        },
        "dns": {
            "name": "配置DNS",
            "commands": [
                f"echo 'nameserver {dns}' > /etc/resolv.conf",
                f"echo 'nameserver {dns2}' >> /etc/resolv.conf",
                "cat /etc/resolv.conf",
                "nslookup baidu.com",
            ],
            "tips": ["直接编辑 /etc/resolv.conf 重启后可能丢失", "建议用 nmcli con mod 配置DNS更持久"],
        },
        "hosts": {
            "name": "配置hosts文件",
            "commands": [
                f"echo '{ip} {hostname}' >> /etc/hosts",
                "cat /etc/hosts",
                f"ping -c 1 {hostname}",
            ],
        },
        "hostname": {
            "name": "设置主机名",
            "commands": [
                f"hostnamectl set-hostname {hostname}",
                "hostnamectl",
                "cat /etc/hostname",
            ],
        },
        "route-add": {
            "name": "添加静态路由",
            "commands": [
                f"ip route add {network} via {route_gw}",
                "ip route show",
            ],
            "tips": ["路由在重启后失效", "持久化: 编辑 /etc/sysconfig/network-scripts/route-{connection}"],
        },
        "route-show": {
            "name": "查看路由表",
            "commands": [
                "ip route show",
                "echo '---策略路由---'",
                "ip rule show",
                "echo '---路由缓存---'",
                "ip route show cache",
            ],
        },
        "vlan": {
            "name": "配置VLAN",
            "commands": [
                f"ip link add link {connection} name {connection}.{config.get('vlan_id', '100')} type vlan id {config.get('vlan_id', '100')}",
                f"ip addr add {ip}/{mask} dev {connection}.{config.get('vlan_id', '100')}",
                f"ip link set dev {connection}.{config.get('vlan_id', '100')} up",
                "ip -d link show",
            ],
            "tips": ["需要内核8021q模块支持", "modprobe 8021q 加载模块"],
        },
        "bond": {
            "name": "配置网卡绑定( Bond )",
            "commands": [
                "ip link add bond0 type bond mode active-backup",
                f"ip link set {connection} master bond0",
                f"ip addr add {ip}/{mask} dev bond0",
                "ip link set bond0 up",
                "cat /proc/net/bonding/bond0",
            ],
            "tips": ["mode: active-backup(主备), balance-rr(轮询), balance-xor(负载均衡)", "需要先加载 bonding 模块"],
        },
        "bridge": {
            "name": "配置网桥",
            "commands": [
                "ip link add br0 type bridge",
                f"ip link set {connection} master br0",
                f"ip addr add {ip}/{mask} dev br0",
                "ip link set br0 up",
                "bridge link show",
            ],
        },
        "firewall-cmd": {
            "name": "firewalld防火墙配置",
            "commands": [
                "firewall-cmd --state",
                "firewall-cmd --get-active-zones",
                "firewall-cmd --list-all",
                f"firewall-cmd --add-port={config.get('port', '80')}/tcp --permanent",
                "firewall-cmd --reload",
            ],
        },
    }

    if action in actions:
        entry = actions[action].copy()
        # 替换变量
        entry["commands"] = [c.replace("{connection}", connection).replace("{ip}", ip)
                             .replace("{mask}", mask).replace("{hostname}", hostname)
                             for c in entry["commands"]]
        return {"success": True, "action": action, **entry}
    else:
        return {"success": False, "error": f"未知操作: {action}", "available": list(actions.keys())}


# ============ DNS 配置 ============

def dns_config(action: str, config: dict = None) -> dict:
    """DNS服务器配置"""
    config = config or {}
    domain = config.get("domain", "example.com")
    zone_ip = config.get("zone_ip", "192.168.1.100")
    dns_ip = config.get("dns_ip", "192.168.1.10")

    actions = {
        "install": {
            "name": "安装DNS服务(BIND)",
            "commands": [
                "# CentOS/RHEL",
                "yum install -y bind bind-utils",
                "# Ubuntu/Debian",
                "apt install -y bind9 bind9utils",
                "systemctl enable named",
                "systemctl start named",
            ],
        },
        "config-master": {
            "name": "配置主DNS服务器",
            "commands": [
                "# 编辑主配置文件",
                "cat > /etc/named.conf << 'EOF'",
                "options {",
                "    listen-on port 53 { any; };",
                "    directory \"/var/named\";",
                "    allow-query { any; };",
                "    recursion no;",
                "};",
                f"zone \"{domain}\" IN {{",
                "    type master;",
                f"    file \"named.{domain}\";",
                "    allow-update { none; };",
                "};",
                "EOF",
                "",
                "# 创建区域文件",
                f"cat > /var/named/named.{domain} << 'EOF'",
                "$TTL 86400",
                f"@   IN  SOA  ns1.{domain}. admin.{domain}. (",
                "        2024010101  ; Serial",
                "        3600        ; Refresh",
                "        1800        ; Retry",
                "        604800      ; Expire",
                "        86400       ; Minimum TTL",
                ")",
                f"@       IN  NS   ns1.{domain}.",
                f"ns1     IN  A    {dns_ip}",
                f"@       IN  A    {zone_ip}",
                f"www     IN  A    {zone_ip}",
                f"mail    IN  A    {zone_ip}",
                f"@       IN  MX 10 mail.{domain}.",
                "EOF",
                "",
                "systemctl restart named",
                "named-checkconf",
                f"named-checkzone {domain} /var/named/named.{domain}",
            ],
            "tips": ["修改区域文件后需增加Serial号", "named-checkconf 检查配置语法", "named-checkzone 检查区域文件"],
        },
        "config-slave": {
            "name": "配置从DNS服务器",
            "commands": [
                "cat > /etc/named.conf << 'EOF'",
                "options {",
                "    listen-on port 53 { any; };",
                "    directory \"/var/named\";",
                "    allow-query { any; };",
                "    recursion no;",
                "};",
                f"zone \"{domain}\" IN {{",
                "    type slave;",
                f"    masters {{ {dns_ip}; }};",
                f"    file \"slaves/named.{domain}\";",
                "};",
                "EOF",
                "systemctl restart named",
            ],
        },
        "test": {
            "name": "测试DNS解析",
            "commands": [
                f"nslookup www.{domain} {dns_ip}",
                f"dig @{dns_ip} www.{domain} A",
                f"dig @{dns_ip} {domain} MX",
                f"dig @{dns_ip} {domain} NS",
                "cat /etc/resolv.conf",
            ],
        },
        "reverse": {
            "name": "配置反向解析",
            "commands": [
                "# 在named.conf添加反向区域",
                f"# zone \"1.168.192.in-addr.arpa\" IN {{",
                "#     type master;",
                f"#     file \"named.192.168.1\";",
                "# };",
                "",
                "# 创建反向区域文件",
                f"cat > /var/named/named.192.168.1 << 'EOF'",
                "$TTL 86400",
                f"@   IN  SOA  ns1.{domain}. admin.{domain}. (",
                "        2024010101",
                "        3600",
                "        1800",
                "        604800",
                "        86400",
                ")",
                f"@       IN  NS   ns1.{domain}.",
                "100     IN  PTR  www.example.com.",
                "EOF",
                "systemctl restart named",
                f"dig @{dns_ip} -x 192.168.1.100",
            ],
        },
    }

    if action in actions:
        entry = actions[action].copy()
        return {"success": True, "action": action, **entry}
    return {"success": False, "error": f"未知操作: {action}", "available": list(actions.keys())}


# ============ DHCP 配置 ============

def dhcp_config(action: str, config: dict = None) -> dict:
    """DHCP服务器配置"""
    config = config or {}
    subnet = config.get("subnet", "192.168.1.0")
    netmask = config.get("netmask", "255.255.255.0")
    range_start = config.get("range_start", "192.168.1.100")
    range_end = config.get("range_end", "192.168.1.200")
    gateway = config.get("gateway", "192.168.1.1")
    dns = config.get("dns", "8.8.8.8")
    lease_time = config.get("lease_time", "86400")

    actions = {
        "install": {
            "name": "安装DHCP服务",
            "commands": [
                "# CentOS/RHEL",
                "yum install -y dhcp",
                "# Ubuntu/Debian",
                "apt install -y isc-dhcp-server",
                "systemctl enable dhcpd",
            ],
        },
        "config": {
            "name": "配置DHCP服务器",
            "commands": [
                "cat > /etc/dhcp/dhcpd.conf << 'EOF'",
                "default-lease-time 600;",
                "max-lease-time 7200;",
                "authoritative;",
                "",
                f"subnet {subnet} netmask {netmask} {{",
                f"    range {range_start} {range_end};",
                f"    option routers {gateway};",
                f"    option domain-name-servers {dns};",
                f"    option broadcast-address {subnet.rsplit('.', 1)[0]}.255;",
                f"    default-lease-time {lease_time};",
                f"    max-lease-time {int(lease_time) * 2};",
                "}",
                "",
                "# 静态IP绑定（可选）",
                "# host server01 {",
                "#     hardware ethernet 00:0C:29:XX:XX:XX;",
                "#     fixed-address 192.168.1.10;",
                "# }",
                "EOF",
                "systemctl restart dhcpd",
            ],
            "tips": ["range 定义可分配的IP范围", "静态绑定需要客户端MAC地址", "修改配置后需重启服务"],
        },
        "test": {
            "name": "测试DHCP",
            "commands": [
                "systemctl status dhcpd",
                "cat /var/lib/dhcpd/dhcpd.leases",
                "# 客户端测试:",
                "dhclient -v ens33",
                "ip addr show",
            ],
        },
    }

    if action in actions:
        entry = actions[action].copy()
        return {"success": True, "action": action, **entry}
    return {"success": False, "error": f"未知操作: {action}", "available": list(actions.keys())}


# ============ 网络诊断 ============

def network_diagnose(action: str, config: dict = None) -> dict:
    """网络诊断工具"""
    config = config or {}
    target = config.get("target", "8.8.8.8")
    port = config.get("port", "80")
    interface = config.get("interface", "ens33")

    actions = {
        "ping": {
            "name": "连通性测试",
            "commands": [
                f"ping -c 4 {target}",
                f"ping -c 4 -I {interface} {target}",
            ],
        },
        "traceroute": {
            "name": "路由追踪",
            "commands": [
                f"traceroute {target}",
                f"tracepath {target}",
            ],
        },
        "port-check": {
            "name": "端口连通性检测",
            "commands": [
                f"nc -zv {target} {port}",
                f"telnet {target} {port}",
                f"nmap -p {port} {target}",
                f"ss -tlnp | grep :{port}",
            ],
        },
        "dns-check": {
            "name": "DNS解析检测",
            "commands": [
                f"nslookup {target}",
                f"dig {target}",
                f"dig {target} +short",
                "cat /etc/resolv.conf",
            ],
        },
        "netstat": {
            "name": "网络连接状态",
            "commands": [
                "ss -tlnp",
                "ss -ulnp",
                "ss -s",
                "netstat -tlnp",
                "netstat -anp",
            ],
        },
        "tcpdump": {
            "name": "抓包分析",
            "commands": [
                f"tcpdump -i {interface} -c 100",
                f"tcpdump -i {interface} host {target}",
                f"tcpdump -i {interface} port {port}",
                f"tcpdump -i {interface} -w capture.pcap",
                "tcpdump -r capture.pcap",
            ],
            "tips": ["-c 限制抓包数量", "-w 写入文件", "-r 读取pcap文件"],
        },
        "bandwidth": {
            "name": "带宽测试",
            "commands": [
                "# 安装iperf3",
                "yum install -y iperf3  # 或 apt install iperf3",
                "# 服务端",
                "iperf3 -s",
                "# 客户端",
                f"iperf3 -c {target}",
                f"iperf3 -c {target} -t 10 -P 4",
            ],
        },
        "arp": {
            "name": "ARP表查看",
            "commands": [
                "arp -a",
                "ip neigh show",
                "arping -c 3 -I {interface} {target}",
            ],
        },
    }

    if action in actions:
        entry = actions[action].copy()
        entry["commands"] = [c.replace("{target}", target).replace("{port}", str(port))
                             .replace("{interface}", interface) for c in entry["commands"]]
        return {"success": True, "action": action, **entry}
    return {"success": False, "error": f"未知操作: {action}", "available": list(actions.keys())}


# ============ 网络服务管理 ============

def service_config(action: str, config: dict = None) -> dict:
    """网络服务管理"""
    config = config or {}
    service = config.get("service", "httpd")
    port = config.get("port", "80")

    actions = {
        "ssh": {
            "name": "SSH服务配置",
            "commands": [
                "systemctl status sshd",
                "systemctl enable sshd",
                "systemctl start sshd",
                "# 修改SSH端口",
                f"# sed -i 's/#Port 22/Port {port}/' /etc/ssh/sshd_config",
                "# 禁止root登录",
                "# sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                "# systemctl restart sshd",
                "ss -tlnp | grep sshd",
            ],
            "tips": ["修改端口后需更新防火墙规则", "禁止root登录前确保有其他用户可用"],
        },
        "httpd": {
            "name": "Apache HTTP服务",
            "commands": [
                "yum install -y httpd",
                "systemctl enable httpd",
                "systemctl start httpd",
                "firewall-cmd --add-service=http --permanent",
                "firewall-cmd --add-service=https --permanent",
                "firewall-cmd --reload",
                "curl -I http://localhost",
            ],
        },
        "nginx": {
            "name": "Nginx服务",
            "commands": [
                "yum install -y nginx",
                "systemctl enable nginx",
                "systemctl start nginx",
                "nginx -t",
                "curl -I http://localhost",
            ],
        },
        "vsftpd": {
            "name": "FTP服务(vsftpd)",
            "commands": [
                "yum install -y vsftpd",
                "systemctl enable vsftpd",
                "systemctl start vsftpd",
                "firewall-cmd --add-service=ftp --permanent",
                "firewall-cmd --reload",
                "cat /etc/vsftpd/vsftpd.conf",
            ],
        },
        "chrony": {
            "name": "时间同步服务(NTP)",
            "commands": [
                "yum install -y chrony",
                "systemctl enable chrond",
                "systemctl start chrond",
                "chronyc sources -v",
                "timedatectl status",
            ],
        },
    }

    if action in actions:
        entry = actions[action].copy()
        entry["commands"] = [c.replace("{port}", str(port)) for c in entry["commands"]]
        return {"success": True, "action": action, **entry}
    return {"success": False, "error": f"未知操作: {action}", "available": list(actions.keys())}


# ============ 竞赛网络题目 ============

def competition_network_task(task_num: int, config: dict = None) -> dict:
    """竞赛信息网络题目模板"""
    config = config or {}

    tasks = {
        1: {
            "name": "子网划分",
            "description": "将给定网络划分为指定数量的子网",
            "example": "将192.168.1.0/24划分为4个子网",
            "solution": subnet_split(config.get("network", "192.168.1.0/24"), config.get("new_prefix", 26)),
            "commands": [
                "# 子网划分思路",
                "# 1. 确定需要的子网数: 4个子网需要2位主机位",
                "# 2. 新前缀 = 原前缀 + 2 = 24 + 2 = 26",
                "# 3. 每个子网有 2^(32-26) - 2 = 62 个可用主机",
                "ipcalc 192.168.1.0/26",
                "ipcalc 192.168.1.64/26",
                "ipcalc 192.168.1.128/26",
                "ipcalc 192.168.1.192/26",
            ],
            "tips": ["子网数 = 2^n，n为借用的主机位数", "每个子网可用主机数 = 2^(32-新前缀) - 2"],
        },
        2: {
            "name": "静态IP配置",
            "description": "配置服务器静态IP地址",
            "example": "配置ens33为192.168.1.100/24，网关192.168.1.1",
            "commands": [
                f"nmcli con mod {config.get('connection', 'ens33')} ipv4.addresses {config.get('ip', '192.168.1.100')}/{config.get('mask', '24')}",
                f"nmcli con mod {config.get('connection', 'ens33')} ipv4.gateway {config.get('gateway', '192.168.1.1')}",
                f"nmcli con mod {config.get('connection', 'ens33')} ipv4.dns {config.get('dns', '8.8.8.8')}",
                f"nmcli con mod {config.get('connection', 'ens33')} ipv4.method manual",
                f"nmcli con up {config.get('connection', 'ens33')}",
                "ip addr show",
                "ip route show",
            ],
            "tips": ["先用 nmcli con show 查看连接名", "配置后用 ip addr show 验证"],
        },
        3: {
            "name": "DNS服务器配置",
            "description": "配置BIND DNS服务器",
            "example": "配置example.com的DNS解析",
            "commands": [
                "yum install -y bind bind-utils",
                "# 编辑 /etc/named.conf 配置监听和区域",
                "# 创建区域文件 /var/named/named.example.com",
                "systemctl enable named",
                "systemctl start named",
                "named-checkconf",
                "named-checkzone example.com /var/named/named.example.com",
                "dig @localhost www.example.com",
            ],
            "tips": ["修改区域文件后需增加Serial号", "用named-checkconf检查语法"],
        },
        4: {
            "name": "DHCP服务器配置",
            "description": "配置DHCP服务器分配IP",
            "example": "配置192.168.1.0/24的DHCP，范围100-200",
            "commands": [
                "yum install -y dhcp",
                "# 编辑 /etc/dhcp/dhcpd.conf",
                "systemctl enable dhcpd",
                "systemctl start dhcpd",
                "cat /var/lib/dhcpd/dhcpd.leases",
            ],
            "tips": ["确保DHCP服务器有静态IP", "配置文件语法错误会导致服务启动失败"],
        },
        5: {
            "name": "网络故障排除",
            "description": "诊断并修复网络连接问题",
            "example": "服务器无法访问外网，排查原因",
            "commands": [
                "# 1. 检查网卡状态",
                "ip addr show",
                "# 2. 检查路由",
                "ip route show",
                "# 3. 检查DNS",
                "cat /etc/resolv.conf",
                "nslookup baidu.com",
                "# 4. 测试连通性",
                "ping -c 3 192.168.1.1",
                "ping -c 3 8.8.8.8",
                "# 5. 检查防火墙",
                "iptables -L -n",
                "firewall-cmd --list-all",
                "# 6. 检查端口监听",
                "ss -tlnp",
            ],
            "tips": ["按层排查: 物理层->数据链路层->网络层->应用层", "ping网关测试二层连通性", "ping 8.8.8.8测试三层连通性", "nslookup测试DNS"],
        },
        6: {
            "name": "VLAN配置",
            "description": "配置VLAN划分网络",
            "example": "在ens33上创建VLAN 100，IP为10.0.100.1/24",
            "commands": [
                "modprobe 8021q",
                f"ip link add link {config.get('connection', 'ens33')} name {config.get('connection', 'ens33')}.{config.get('vlan_id', '100')} type vlan id {config.get('vlan_id', '100')}",
                f"ip addr add {config.get('ip', '10.0.100.1')}/{config.get('mask', '24')} dev {config.get('connection', 'ens33')}.{config.get('vlan_id', '100')}",
                f"ip link set dev {config.get('connection', 'ens33')}.{config.get('vlan_id', '100')} up",
                "ip -d link show",
            ],
        },
        7: {
            "name": "路由配置",
            "description": "配置静态路由实现跨网段通信",
            "example": "添加到10.0.0.0/8网段的路由，下一跳192.168.1.254",
            "commands": [
                f"ip route add {config.get('network', '10.0.0.0/8')} via {config.get('route_gateway', '192.168.1.254')}",
                "ip route show",
                f"ping -c 3 {config.get('test_ip', '10.0.0.1')}",
            ],
            "tips": ["确保下一跳可达", "持久化需写入配置文件"],
        },
        8: {
            "name": "NTP时间同步",
            "description": "配置时间同步服务",
            "example": "配置chrony同步NTP服务器",
            "commands": [
                "yum install -y chrony",
                "# 编辑 /etc/chrony.conf 添加NTP服务器",
                "systemctl enable chronyd",
                "systemctl start chronyd",
                "chronyc sources -v",
                "timedatectl status",
            ],
        },
    }

    if task_num not in tasks:
        return {"success": False, "error": f"没有任务{task_num}", "available": list(tasks.keys())}

    task = tasks[task_num].copy()
    task["success"] = True
    if isinstance(task.get("solution"), dict):
        task["solution"]["success"] = True
    return task


# ============ 场景列表 ============

def list_scenarios() -> dict:
    """列出所有可用场景"""
    return {
        "网络配置": ["show", "static-ip", "dhcp", "dns", "hosts", "hostname", "route-add", "route-show", "vlan", "bond", "bridge", "firewall-cmd"],
        "DNS服务": ["install", "config-master", "config-slave", "test", "reverse"],
        "DHCP服务": ["install", "config", "test"],
        "网络诊断": ["ping", "traceroute", "port-check", "dns-check", "netstat", "tcpdump", "bandwidth", "arp"],
        "网络服务": ["ssh", "httpd", "nginx", "vsftpd", "chrony"],
    }
