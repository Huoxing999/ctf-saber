"""防火墙规则生成模块 - iptables/nftables/Windows防火墙 + 竞赛题目"""


def _apply_config(rules: list[str], config: dict) -> list[str]:
    """将config中的变量替换到规则模板中"""
    if not config:
        return rules
    result = []
    for rule in rules:
        for key, value in config.items():
            rule = rule.replace(f'{{{key}}}', str(value))
        result.append(rule)
    return result


# ============ iptables 规则库 ============

IPTABLES_RULES = {
    "白名单_只允许指定IP": {
        "description": "只允许指定IP访问服务器，其他全部拒绝",
        "category": "访问控制",
        "rules": [
            "# 清空现有规则",
            "iptables -F",
            "# 允许已建立的连接",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "# 允许回环接口",
            "iptables -A INPUT -i lo -j ACCEPT",
            "# 允许指定IP（替换为实际IP）",
            "iptables -A INPUT -s {allowed_ip} -j ACCEPT",
            "# 拒绝其他所有",
            "iptables -A INPUT -j DROP",
        ],
        "variables": {"allowed_ip": "需要允许的IP地址"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "白名单_多IP": {
        "description": "允许多个指定IP访问",
        "category": "访问控制",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -s {ip1} -j ACCEPT",
            "iptables -A INPUT -s {ip2} -j ACCEPT",
            "iptables -A INPUT -s {ip3} -j ACCEPT",
            "iptables -A INPUT -j DROP",
        ],
        "variables": {"ip1": "IP地址1", "ip2": "IP地址2", "ip3": "IP地址3"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "黑名单_禁止指定IP": {
        "description": "禁止指定IP访问，其他允许",
        "category": "访问控制",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -s {blocked_ip} -j DROP",
            "iptables -A INPUT -j ACCEPT",
        ],
        "variables": {"blocked_ip": "需要禁止的IP地址"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "端口限制_只开放指定端口": {
        "description": "只开放指定端口（如80和443），其他全部关闭",
        "category": "端口管理",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport {port1} -j ACCEPT",
            "iptables -A INPUT -p tcp --dport {port2} -j ACCEPT",
            "iptables -A INPUT -j DROP",
        ],
        "variables": {"port1": "端口1（如80）", "port2": "端口2（如443）"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "SSH安全加固": {
        "description": "SSH服务安全加固：限制来源IP、防暴力破解",
        "category": "服务加固",
        "rules": [
            "# 允许已建立的SSH连接",
            "iptables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "# 限制SSH来源IP段",
            "iptables -A INPUT -p tcp --dport 22 -s {ssh_subnet} -j ACCEPT",
            "# 限制SSH连接频率（防暴力破解）",
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH",
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP",
            "# 记录被拒绝的SSH尝试",
            "iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix 'SSH_REJECTED: '",
            "iptables -A INPUT -p tcp --dport 22 -j DROP",
        ],
        "variables": {"ssh_subnet": "允许SSH的网段（如192.168.1.0/24）"},
        "verify": ["iptables -L INPUT -n -v --line-numbers", "tail -f /var/log/messages | grep SSH"],
    },
    "Web应用防护": {
        "description": "Web服务器综合防护：端口限制+连接数+SYN防护",
        "category": "服务加固",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "# SSH管理",
            "iptables -A INPUT -p tcp --dport 22 -s {admin_ip} -j ACCEPT",
            "# HTTP/HTTPS",
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            "# 限制单IP并发连接数",
            "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above {max_conn} -j REJECT",
            "iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above {max_conn} -j REJECT",
            "# SYN洪水防护",
            "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
            "# ICMP限制",
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
            "# 其他全部拒绝",
            "iptables -A INPUT -j DROP",
            "iptables -A FORWARD -j DROP",
        ],
        "variables": {"admin_ip": "管理IP（SSH白名单）", "max_conn": "单IP最大连接数（如50）"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "数据库服务器加固": {
        "description": "数据库服务器安全配置：仅允许内网访问",
        "category": "服务加固",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "# SSH管理",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "# MySQL仅允许内网",
            "iptables -A INPUT -s {db_subnet} -p tcp --dport {db_port} -j ACCEPT",
            "iptables -A INPUT -p tcp --dport {db_port} -j DROP",
            "# 记录非法数据库访问",
            "iptables -A INPUT -p tcp --dport {db_port} -j LOG --log-prefix 'DB_BLOCKED: '",
            "iptables -A INPUT -j DROP",
        ],
        "variables": {"db_subnet": "数据库访问网段（如192.168.0.0/16）", "db_port": "数据库端口（如3306）"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "防SYN洪水攻击": {
        "description": "防御SYN Flood攻击",
        "category": "攻击防护",
        "rules": [
            "echo 1 > /proc/sys/net/ipv4/tcp_syncookies",
            "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
        ],
        "verify": ["sysctl net.ipv4.tcp_syncookies", "iptables -L INPUT -n -v"],
    },
    "防端口扫描": {
        "description": "检测和阻止端口扫描",
        "category": "攻击防护",
        "rules": [
            "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP",
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
        ],
        "verify": ["iptables -L INPUT -n -v"],
    },
    "NAT端口转发": {
        "description": "将外部端口转发到内网服务器",
        "category": "NAT/转发",
        "rules": [
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "iptables -t nat -A PREROUTING -p tcp --dport {ext_port} -j DNAT --to-destination {internal_ip}:{int_port}",
            "iptables -A FORWARD -p tcp -d {internal_ip} --dport {int_port} -j ACCEPT",
            "iptables -t nat -A POSTROUTING -d {internal_ip} -p tcp --dport {int_port} -j MASQUERADE",
        ],
        "variables": {"ext_port": "外部端口", "internal_ip": "内网服务器IP", "int_port": "内网服务端口"},
        "verify": ["iptables -t nat -L -n -v", "iptables -L FORWARD -n -v"],
    },
    "限制特定端口访问频率": {
        "description": "限制对特定端口的访问频率（防暴力破解）",
        "category": "攻击防护",
        "rules": [
            "iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --set",
            "iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP",
            "iptables -A INPUT -p tcp --dport {port} -j ACCEPT",
        ],
        "variables": {"port": "需要限制的端口（如22）"},
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "日志记录规则": {
        "description": "记录被拒绝的连接到日志（用于审计）",
        "category": "日志审计",
        "rules": [
            "# 记录所有被INPUT链DROP的数据包",
            "iptables -A INPUT -j LOG --log-prefix 'IPT_INPUT_DROP: ' --log-level 4",
            "# 记录所有被FORWARD链DROP的数据包",
            "iptables -A FORWARD -j LOG --log-prefix 'IPT_FORWARD_DROP: ' --log-level 4",
            "# 记录非法TCP标志",
            "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix 'IPT_NULL_SCAN: '",
            "iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix 'IPT_XMAS_SCAN: '",
        ],
        "verify": ["tail -f /var/log/messages | grep IPT_"],
    },
    "ICMP控制": {
        "description": "ICMP(ping)流量控制",
        "category": "网络控制",
        "rules": [
            "# 允许入站ping（限速）",
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {rate} -j ACCEPT",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
            "# 允许出站ping",
            "iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT",
            "iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT",
        ],
        "variables": {"rate": "限速（如1/s, 5/s）"},
        "verify": ["iptables -L INPUT -n -v | grep icmp"],
    },
    "端口敲门": {
        "description": "端口敲门（Port Knocking）：按顺序访问端口后才开放SSH",
        "category": "高级防护",
        "rules": [
            "# 创建敲门链",
            "iptables -N KNOCKING",
            "iptables -A INPUT -j KNOCKING",
            "# 第一步：访问端口1",
            "iptables -A KNOCKING -p tcp --dport {port1} -m recent --name STEP1 --set",
            "iptables -A KNOCKING -p tcp --dport {port1} -j DROP",
            "# 第二步：访问端口2（必须在第一步之后）",
            "iptables -A KNOCKING -p tcp --dport {port2} -m recent --name STEP1 --remove -m recent --name STEP2 --set",
            "iptables -A KNOCKING -p tcp --dport {port2} -j DROP",
            "# 第三步：访问端口3后开放SSH",
            "iptables -A KNOCKING -p tcp --dport {port3} -m recent --name STEP2 --remove -m recent --name AUTH --set",
            "iptables -A KNOCKING -p tcp --dport {port3} -j DROP",
            "# 检查敲门成功后允许SSH",
            "iptables -A KNOCKING -p tcp --dport 22 -m recent --name AUTH --seconds 10 -j ACCEPT",
        ],
        "variables": {"port1": "敲门端口1（如7000）", "port2": "敲门端口2（如8000）", "port3": "敲门端口3（如9000）"},
        "verify": ["iptables -L KNOCKING -n -v"],
    },
}

IPTABLES_PRESETS = {
    "web服务器": {
        "description": "标准Web服务器安全配置",
        "category": "服务器预设",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT",
            "iptables -A INPUT -j DROP",
            "iptables -A FORWARD -j DROP",
        ],
        "verify": ["iptables -L -n -v"],
    },
    "数据库服务器": {
        "description": "数据库服务器安全配置（仅允许内网访问）",
        "category": "服务器预设",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -s 192.168.0.0/16 -p tcp --dport 3306 -j ACCEPT",
            "iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 3306 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 3306 -j DROP",
            "iptables -A INPUT -j DROP",
        ],
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "邮件服务器": {
        "description": "邮件服务器安全配置",
        "category": "服务器预设",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 25 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 465 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 587 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 110 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 143 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 993 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 995 -j ACCEPT",
            "iptables -A INPUT -j DROP",
        ],
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "DNS服务器": {
        "description": "DNS服务器安全配置",
        "category": "服务器预设",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p udp --dport 53 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 53 -j ACCEPT",
            "iptables -A INPUT -j DROP",
        ],
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "FTP服务器": {
        "description": "FTP服务器安全配置（主动+被动模式）",
        "category": "服务器预设",
        "rules": [
            "iptables -F",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "# FTP控制端口",
            "iptables -A INPUT -p tcp --dport 21 -j ACCEPT",
            "# FTP主动模式数据端口",
            "iptables -A INPUT -p tcp --dport 20 -j ACCEPT",
            "# FTP被动模式端口范围",
            "iptables -A INPUT -p tcp --dport 49152:65535 -j ACCEPT",
            "iptables -A INPUT -j DROP",
        ],
        "verify": ["iptables -L INPUT -n -v --line-numbers"],
    },
    "综合加固": {
        "description": "服务器综合安全加固（推荐）",
        "category": "服务器预设",
        "rules": [
            "# 清空规则",
            "iptables -F",
            "iptables -X",
            "# 设置默认策略",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",
            "# 允许已建立连接",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "# 允许回环",
            "iptables -A INPUT -i lo -j ACCEPT",
            "# SSH（限速防爆破）",
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH",
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "# HTTP/HTTPS",
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            "# ICMP限速",
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
            "# 防端口扫描",
            "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
            "# 记录并丢弃其他",
            "iptables -A INPUT -j LOG --log-prefix 'FW_DROP: '",
            "iptables -A INPUT -j DROP",
        ],
        "verify": ["iptables -L -n -v", "iptables -L -n --line-numbers"],
    },
}


def generate_iptables_rules(scenario: str, config: dict = None) -> dict:
    """根据场景生成iptables规则"""
    if scenario in IPTABLES_RULES:
        entry = IPTABLES_RULES[scenario].copy()
        entry["rules"] = _apply_config(entry["rules"], config)
        entry["platform"] = "iptables"
        return entry
    elif scenario in IPTABLES_PRESETS:
        entry = IPTABLES_PRESETS[scenario].copy()
        entry["rules"] = _apply_config(entry["rules"], config)
        entry["platform"] = "iptables"
        return entry
    else:
        return {
            "available_scenarios": list(IPTABLES_RULES.keys()),
            "available_presets": list(IPTABLES_PRESETS.keys()),
            "message": "未知场景，请选择可用场景"
        }


# ============ nftables 规则库 ============

NFTABLES_RULES = {
    "web服务器": {
        "description": "nftables Web服务器配置",
        "category": "服务器预设",
        "rules": [
            "#!/usr/sbin/nft -f",
            "flush ruleset",
            "table inet filter {",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "        ct state established,related accept",
            "        iif lo accept",
            "        tcp dport 22 accept",
            "        tcp dport 80 accept",
            "        tcp dport 443 accept",
            "        icmp type echo-request accept",
            "    }",
            "    chain forward {",
            "        type filter hook forward priority 0; policy drop;",
            "    }",
            "    chain output {",
            "        type filter hook output priority 0; policy accept;",
            "    }",
            "}",
        ],
        "verify": ["nft list ruleset"],
    },
    "数据库服务器": {
        "description": "nftables 数据库服务器配置",
        "category": "服务器预设",
        "rules": [
            "#!/usr/sbin/nft -f",
            "flush ruleset",
            "table inet filter {",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "        ct state established,related accept",
            "        iif lo accept",
            "        tcp dport 22 accept",
            "        ip saddr 192.168.0.0/16 tcp dport 3306 accept",
            "        ip saddr 10.0.0.0/8 tcp dport 3306 accept",
            "        tcp dport 3306 drop",
            "    }",
            "}",
        ],
        "verify": ["nft list ruleset"],
    },
    "综合加固": {
        "description": "nftables 综合安全加固",
        "category": "服务器预设",
        "rules": [
            "#!/usr/sbin/nft -f",
            "flush ruleset",
            "table inet filter {",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "        ct state established,related accept",
            "        ct state invalid drop",
            "        iif lo accept",
            "        tcp dport 22 ct state new limit rate 4/minute accept",
            "        tcp dport 80 accept",
            "        tcp dport 443 accept",
            "        icmp type echo-request limit rate 1/second accept",
            "        tcp flags & (fin|syn|rst|ack) == syn ct state new limit rate 10/second accept",
            "        tcp flags & (fin|syn|rst|psh|urg) == fin|syn|rst|psh|urg drop",
            "        tcp flags & (fin|syn|rst|psh|urg) == 0 drop",
            "        log prefix \"nft_drop: \" drop",
            "    }",
            "    chain forward {",
            "        type filter hook forward priority 0; policy drop;",
            "    }",
            "    chain output {",
            "        type filter hook output priority 0; policy accept;",
            "    }",
            "}",
        ],
        "verify": ["nft list ruleset"],
    },
    "白名单访问控制": {
        "description": "nftables 白名单访问控制",
        "category": "访问控制",
        "rules": [
            "#!/usr/sbin/nft -f",
            "flush ruleset",
            "table inet filter {",
            "    set whitelist {",
            "        type ipv4_addr",
            "        elements = {{allowed_ip}}",
            "    }",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "        ct state established,related accept",
            "        iif lo accept",
            "        ip saddr @whitelist accept",
            "    }",
            "}",
        ],
        "variables": {"allowed_ip": "允许的IP地址（逗号分隔）"},
        "verify": ["nft list ruleset", "nft list set inet filter whitelist"],
    },
    "端口限速": {
        "description": "nftables 端口连接限速",
        "category": "攻击防护",
        "rules": [
            "#!/usr/sbin/nft -f",
            "flush ruleset",
            "table inet filter {",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "        ct state established,related accept",
            "        iif lo accept",
            "        tcp dport {port} ct state new limit rate {rate} accept",
            "        tcp dport {port} ct state new drop",
            "        tcp dport 22 accept",
            "    }",
            "}",
        ],
        "variables": {"port": "限速端口（如80）", "rate": "限速（如10/second）"},
        "verify": ["nft list ruleset"],
    },
}


def generate_nftables_rules(scenario: str, config: dict = None) -> dict:
    """生成nftables规则（现代Linux默认）"""
    if scenario in NFTABLES_RULES:
        entry = NFTABLES_RULES[scenario].copy()
        entry["rules"] = _apply_config(entry["rules"], config)
        entry["platform"] = "nftables"
        return entry
    return {"message": "nftables暂不支持该场景", "available": list(NFTABLES_RULES.keys())}


# ============ Windows 防火墙规则库 ============

WINDOWS_RULES = {
    "web服务器": {
        "description": "Windows防火墙 Web服务器配置",
        "category": "服务器预设",
        "rules": [
            "# 重置防火墙",
            "netsh advfirewall reset",
            "# 设置默认策略",
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            "# 允许已建立的连接",
            "netsh advfirewall set allprofiles state on",
            "# 允许RDP远程桌面",
            "netsh advfirewall firewall add rule name='Allow RDP' dir=in action=allow protocol=TCP localport=3389",
            "# 允许HTTP",
            "netsh advfirewall firewall add rule name='Allow HTTP' dir=in action=allow protocol=TCP localport=80",
            "# 允许HTTPS",
            "netsh advfirewall firewall add rule name='Allow HTTPS' dir=in action=allow protocol=TCP localport=443",
            "# 允许ICMP(ping)",
            "netsh advfirewall firewall add rule name='Allow ICMPv4' protocol=icmpv4:8,any dir=in action=allow",
        ],
        "verify": ["netsh advfirewall show allprofiles"],
    },
    "数据库服务器": {
        "description": "Windows防火墙 数据库服务器配置",
        "category": "服务器预设",
        "rules": [
            "netsh advfirewall reset",
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            "netsh advfirewall firewall add rule name='Allow RDP' dir=in action=allow protocol=TCP localport=3389",
            "# 仅允许内网访问MySQL",
            "netsh advfirewall firewall add rule name='Allow MySQL Internal' dir=in action=allow protocol=TCP localport=3306 remoteip=192.168.0.0/16,10.0.0.0/8",
            "# 禁止外部访问MySQL",
            "netsh advfirewall firewall add rule name='Block MySQL External' dir=in action=block protocol=TCP localport=3306",
        ],
        "verify": ["netsh advfirewall show allprofiles", "netsh advfirewall firewall show rule name=all"],
    },
    "白名单_只允许指定IP": {
        "description": "Windows防火墙 仅允许指定IP访问",
        "category": "访问控制",
        "rules": [
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            "netsh advfirewall firewall add rule name='Allow RDP' dir=in action=allow protocol=TCP localport=3389",
            "netsh advfirewall firewall add rule name='Allow Trusted IP' dir=in action=allow remoteip={allowed_ip}",
        ],
        "variables": {"allowed_ip": "需要允许的IP地址"},
        "verify": ["netsh advfirewall firewall show rule name=all"],
    },
    "综合加固": {
        "description": "Windows防火墙 综合安全加固",
        "category": "服务器预设",
        "rules": [
            "# 重置防火墙",
            "netsh advfirewall reset",
            "# 开启防火墙",
            "netsh advfirewall set allprofiles state on",
            "# 默认阻止入站",
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            "# 允许RDP",
            "netsh advfirewall firewall add rule name='Allow RDP' dir=in action=allow protocol=TCP localport=3389",
            "# 允许HTTP/HTTPS",
            "netsh advfirewall firewall add rule name='Allow HTTP' dir=in action=allow protocol=TCP localport=80",
            "netsh advfirewall firewall add rule name='Allow HTTPS' dir=in action=allow protocol=TCP localport=443",
            "# 允许ICMP",
            "netsh advfirewall firewall add rule name='Allow ICMPv4' protocol=icmpv4:8,any dir=in action=allow",
            "# 阻止所有其他入站",
            "netsh advfirewall firewall add rule name='Block All Other' dir=in action=block protocol=any",
        ],
        "verify": ["netsh advfirewall show allprofiles", "netsh advfirewall firewall show rule name=all dir=in"],
    },
    "端口限制": {
        "description": "Windows防火墙 端口访问限制",
        "category": "端口管理",
        "rules": [
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
            "netsh advfirewall firewall add rule name='Allow RDP' dir=in action=allow protocol=TCP localport=3389",
            "netsh advfirewall firewall add rule name='Allow Port {port}' dir=in action=allow protocol=TCP localport={port}",
        ],
        "variables": {"port": "需要开放的端口号"},
        "verify": ["netsh advfirewall firewall show rule name=all dir=in"],
    },
}


def generate_windows_rules(scenario: str, config: dict = None) -> dict:
    """生成Windows防火墙规则（netsh advfirewall）"""
    if scenario in WINDOWS_RULES:
        entry = WINDOWS_RULES[scenario].copy()
        entry["rules"] = _apply_config(entry["rules"], config)
        entry["platform"] = "windows"
        return entry
    return {"message": "Windows防火墙暂不支持该场景", "available": list(WINDOWS_RULES.keys())}


# ============ 竞赛题目模板 ============

def competition_firewall_task(task_num: int, config: dict = None) -> dict:
    """竞赛防火墙题目模板"""
    tasks = {
        1: {
            "name": "IP白名单访问控制",
            "description": "只允许指定IP访问特定端口",
            "example": "只允许192.168.1.10和192.168.1.20访问TCP 9000端口",
            "rules": [
                "iptables -F",
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A INPUT -i lo -j ACCEPT",
                "iptables -A INPUT -p tcp --dport {port} -s {ip1} -j ACCEPT",
                "iptables -A INPUT -p tcp --dport {port} -s {ip2} -j ACCEPT",
                "iptables -A INPUT -p tcp --dport {port} -j DROP",
                "iptables -A INPUT -j ACCEPT",
            ],
            "variables": {"port": "目标端口(如9000)", "ip1": "允许的IP1", "ip2": "允许的IP2"},
            "tips": ["注意不要阻断SSH(22端口)", "先允许ESTABLISHED连接避免断连"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        2: {
            "name": "IP黑名单封禁",
            "description": "封禁指定IP的所有入站TCP连接",
            "example": "封禁203.0.113.25在eth0接口的所有TCP入站",
            "rules": [
                "iptables -A INPUT -i {interface} -s {blocked_ip} -p tcp -j DROP",
            ],
            "variables": {"interface": "网卡(如eth0)", "blocked_ip": "要封禁的IP"},
            "tips": ["只在指定接口封禁", "不影响其他接口"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        3: {
            "name": "子网访问+IP排除",
            "description": "允许子网访问但排除特定IP",
            "example": "允许192.168.2.0/24访问TCP 8888，但拒绝192.168.2.10",
            "rules": [
                "iptables -A INPUT -p tcp --dport {port} -s {deny_ip} -j DROP",
                "iptables -A INPUT -p tcp --dport {port} -s {subnet} -j ACCEPT",
                "iptables -A INPUT -p tcp --dport {port} -j DROP",
            ],
            "variables": {"port": "目标端口(如8888)", "subnet": "允许的子网(如192.168.2.0/24)", "deny_ip": "拒绝的IP(如192.168.2.10)"},
            "tips": ["拒绝规则必须在允许规则之前", "iptables按顺序匹配，先匹配到的生效"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        4: {
            "name": "连接数限制",
            "description": "限制单IP的最大并发连接数",
            "example": "限制外部IP访问80端口最多5个并发连接",
            "rules": [
                "iptables -A INPUT -p tcp --dport {port} -m connlimit --connlimit-above {max_conn} -j REJECT",
                "iptables -A INPUT -p tcp --dport {port} -j ACCEPT",
            ],
            "variables": {"port": "目标端口(如80)", "max_conn": "最大连接数(如5)"},
            "tips": ["connlimit模块限制单IP并发数", "REJECT会返回拒绝信息，DROP直接丢弃"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        5: {
            "name": "NAT网关FTP转发",
            "description": "NAT网关+FTP被动模式端口转发",
            "example": "外网通过eth0访问FTP，内网FTP服务器10.0.1.10，内网接口eth1",
            "rules": [
                "# 开启IP转发",
                "echo 1 > /proc/sys/net/ipv4/ip_forward",
                "# NAT伪装",
                "iptables -t nat -A POSTROUTING -o {external_if} -j MASQUERADE",
                "# FTP控制端口转发",
                "iptables -t nat -A PREROUTING -i {external_if} -p tcp --dport 21 -j DNAT --to-destination {ftp_server}:21",
                "iptables -A FORWARD -p tcp -d {ftp_server} --dport 21 -j ACCEPT",
                "# FTP被动模式端口范围转发",
                "iptables -t nat -A PREROUTING -i {external_if} -p tcp --dport {passive_start}:{passive_end} -j DNAT --to-destination {ftp_server}",
                "iptables -A FORWARD -p tcp -d {ftp_server} --dport {passive_start}:{passive_end} -j ACCEPT",
                "# 允许已建立连接",
                "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
            ],
            "variables": {
                "external_if": "外网接口(如eth0)",
                "internal_if": "内网接口(如eth1)",
                "ftp_server": "内网FTP服务器IP(如10.0.1.10)",
                "passive_start": "被动模式起始端口(如49152)",
                "passive_end": "被动模式结束端口(如65535)",
            },
            "tips": ["FTP被动模式需要额外端口范围", "确保ip_forward已开启", "NAT需要PREROUTING+POSTROUTING配合"],
            "verify": ["iptables -t nat -L -n -v", "iptables -L FORWARD -n -v"],
        },
        6: {
            "name": "SSH防暴力破解",
            "description": "限制SSH连接频率，防止暴力破解",
            "example": "限制每分钟最多3次SSH新连接",
            "rules": [
                "iptables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH",
                "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount {max_hits} --name SSH -j DROP",
                "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            ],
            "variables": {"max_hits": "60秒内最大尝试次数(如3)"},
            "tips": ["recent模块跟踪连接状态", "注意不要把自己锁在外面"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        7: {
            "name": "端口范围开放",
            "description": "开放指定端口范围",
            "example": "开放TCP 8000-9000端口范围",
            "rules": [
                "iptables -A INPUT -p tcp --dport {start_port}:{end_port} -j ACCEPT",
            ],
            "variables": {"start_port": "起始端口(如8000)", "end_port": "结束端口(如9000)"},
            "tips": ["端口范围用冒号分隔", "注意端口范围不要过大"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        8: {
            "name": "MAC地址过滤",
            "description": "基于MAC地址的访问控制",
            "example": "只允许MAC为AA:BB:CC:DD:EE:FF的设备访问",
            "rules": [
                "iptables -A INPUT -m mac --mac-source {mac_addr} -j ACCEPT",
                "iptables -A INPUT -j DROP",
            ],
            "variables": {"mac_addr": "允许的MAC地址(如AA:BB:CC:DD:EE:FF)"},
            "tips": ["MAC地址过滤在二层，可被伪造", "通常配合IP白名单使用"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        9: {
            "name": "时间控制规则",
            "description": "基于时间的访问控制",
            "example": "只在工作时间(周一至周五8:00-18:00)允许访问",
            "rules": [
                "iptables -A INPUT -p tcp --dport {port} -m time --timestart 08:00 --timestop 18:00 --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT",
                "iptables -A INPUT -p tcp --dport {port} -j DROP",
            ],
            "variables": {"port": "目标端口(如80)"},
            "tips": ["time模块需要内核支持", "时间基于系统时区"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        10: {
            "name": "多端口综合配置",
            "description": "同时配置多个端口的访问策略",
            "example": "开放22(仅内网)、80、443，封禁3306外部访问",
            "rules": [
                "iptables -F",
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A INPUT -i lo -j ACCEPT",
                "# SSH仅内网",
                "iptables -A INPUT -s {internal_net} -p tcp --dport 22 -j ACCEPT",
                "# Web服务",
                "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
                "# 数据库仅内网",
                "iptables -A INPUT -s {internal_net} -p tcp --dport 3306 -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 3306 -j DROP",
                "# 其他拒绝",
                "iptables -A INPUT -j DROP",
            ],
            "variables": {"internal_net": "内网网段(如192.168.1.0/24)"},
            "tips": ["先配置允许规则，最后配置拒绝规则", "SSH规则限制内网访问更安全"],
            "verify": ["iptables -L INPUT -n -v --line-numbers"],
        },
        11: {
            "name": "防DDoS攻击",
            "description": "配置防DDoS攻击规则",
            "example": "限制SYN包速率、ICMP速率、单IP连接数",
            "rules": [
                "# 开启SYN Cookie",
                "echo 1 > /proc/sys/net/ipv4/tcp_syncookies",
                "# 限制SYN包速率",
                "iptables -A INPUT -p tcp --syn -m limit --limit {syn_rate} --limit-burst {syn_burst} -j ACCEPT",
                "iptables -A INPUT -p tcp --syn -j DROP",
                "# 限制ICMP速率",
                "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {icmp_rate} -j ACCEPT",
                "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
                "# 限制单IP连接数",
                "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above {max_conn} -j REJECT",
            ],
            "variables": {
                "syn_rate": "SYN限速(如1/s)",
                "syn_burst": "SYN突发(如3)",
                "icmp_rate": "ICMP限速(如1/s)",
                "max_conn": "单IP最大连接数(如50)",
            },
            "tips": ["tcp_syncookies是最有效的SYN防护", "limit模块限制匹配速率"],
            "verify": ["sysctl net.ipv4.tcp_syncookies", "iptables -L INPUT -n -v"],
        },
        12: {
            "name": "NAT端口映射",
            "description": "将外部端口映射到内网服务器",
            "example": "将外部8080端口映射到内网192.168.1.100的80端口",
            "rules": [
                "echo 1 > /proc/sys/net/ipv4/ip_forward",
                "iptables -t nat -A PREROUTING -p tcp --dport {ext_port} -j DNAT --to-destination {internal_ip}:{int_port}",
                "iptables -A FORWARD -p tcp -d {internal_ip} --dport {int_port} -j ACCEPT",
                "iptables -t nat -A POSTROUTING -o {external_if} -j MASQUERADE",
            ],
            "variables": {
                "ext_port": "外部端口(如8080)",
                "internal_ip": "内网服务器IP(如192.168.1.100)",
                "int_port": "内网服务端口(如80)",
                "external_if": "外部网卡(如eth0)",
            },
            "tips": ["必须开启ip_forward", "PREROUTING做DNAT，POSTROUTING做SNAT"],
            "verify": ["iptables -t nat -L -n -v", "cat /proc/sys/net/ipv4/ip_forward"],
        },
    }

    if task_num not in tasks:
        return {"success": False, "error": f"没有任务{task_num}", "available": list(tasks.keys())}

    task = tasks[task_num].copy()
    task["success"] = True
    task["rules"] = _apply_config(task["rules"], config)
    task["platform"] = "iptables"
    if "verify" not in task:
        task["verify"] = ["iptables -L -n -v", "iptables -t nat -L -n -v"]
    return task


# ============ 场景列表 ============

def list_scenarios() -> dict:
    """列出所有可用的防火墙场景"""
    return {
        "iptables规则模板": list(IPTABLES_RULES.keys()),
        "iptables预设场景": list(IPTABLES_PRESETS.keys()),
        "nftables预设场景": list(NFTABLES_RULES.keys()),
        "Windows防火墙预设场景": list(WINDOWS_RULES.keys()),
    }


# ============ 规则解析 ============

def explain_rule(rule_line: str) -> dict:
    """解析单条iptables规则的含义"""
    rule = rule_line.strip()
    if not rule or rule.startswith('#'):
        return {"rule": rule_line, "type": "comment", "explanation": "注释行"}

    parts = rule.split()
    if not parts:
        return {"rule": rule_line, "type": "empty", "explanation": "空行"}

    cmd = parts[0]

    if cmd == 'iptables':
        return _explain_iptables(parts)
    elif cmd == 'netsh':
        return _explain_netsh(parts)
    elif cmd == 'echo':
        return {"rule": rule_line, "type": "system", "explanation": "系统参数设置"}
    else:
        return {"rule": rule_line, "type": "other", "explanation": f"命令: {cmd}"}


def _explain_iptables(parts: list) -> dict:
    """解析iptables命令"""
    rule = ' '.join(parts)
    explanation = []
    action = ""
    chain = ""
    target = ""
    proto = ""
    src = ""
    dst = ""
    dport = ""
    extra = []

    i = 1
    while i < len(parts):
        p = parts[i]
        if p == '-A' and i + 1 < len(parts):
            chain = parts[i + 1]; i += 2
        elif p == '-t' and i + 1 < len(parts):
            explanation.append(f"表: {parts[i+1]}"); i += 2
        elif p == '-j' and i + 1 < len(parts):
            target = parts[i + 1]; i += 2
        elif p == '-p' and i + 1 < len(parts):
            proto = parts[i + 1]; i += 2
        elif p == '-s' and i + 1 < len(parts):
            src = parts[i + 1]; i += 2
        elif p == '-d' and i + 1 < len(parts):
            dst = parts[i + 1]; i += 2
        elif p == '--dport' and i + 1 < len(parts):
            dport = parts[i + 1]; i += 2
        elif p == '-i' and i + 1 < len(parts):
            extra.append(f"入接口: {parts[i+1]}"); i += 2
        elif p == '-o' and i + 1 < len(parts):
            extra.append(f"出接口: {parts[i+1]}"); i += 2
        elif p == '-m':
            if i + 1 < len(parts):
                extra.append(f"模块: {parts[i+1]}"); i += 2
            else:
                i += 1
        elif p == '--state' and i + 1 < len(parts):
            extra.append(f"状态: {parts[i+1]}"); i += 2
        elif p == '--icmp-type' and i + 1 < len(parts):
            extra.append(f"ICMP类型: {parts[i+1]}"); i += 2
        elif p == '--limit' and i + 1 < len(parts):
            extra.append(f"限速: {parts[i+1]}"); i += 2
        elif p == '--connlimit-above' and i + 1 < len(parts):
            extra.append(f"连接数上限: {parts[i+1]}"); i += 2
        elif p == '--log-prefix' and i + 1 < len(parts):
            extra.append(f"日志前缀: {parts[i+1]}"); i += 2
        else:
            i += 1

    # 构建解释
    chain_desc = {"INPUT": "入站", "OUTPUT": "出站", "FORWARD": "转发", "PREROUTING": "路由前", "POSTROUTING": "路由后"}
    target_desc = {"ACCEPT": "允许", "DROP": "丢弃", "REJECT": "拒绝", "LOG": "记录日志", "MASQUERADE": "NAT伪装", "DNAT": "目标NAT"}

    desc = f"{chain_desc.get(chain, chain)}链: "
    if proto:
        desc += f"{proto}协议 "
    if src:
        desc += f"来源{src} "
    if dst:
        desc += f"目标{dst} "
    if dport:
        desc += f"端口{dport} "
    desc += f"-> {target_desc.get(target, target)}"
    if extra:
        desc += f" ({', '.join(extra)})"

    return {"rule": rule, "type": "iptables", "explanation": desc, "details": {
        "chain": chain, "target": target, "protocol": proto,
        "source": src, "dest": dst, "dport": dport, "extra": extra
    }}


def _explain_netsh(parts: list) -> dict:
    """解析netsh命令"""
    rule = ' '.join(parts)
    if 'add rule' in rule:
        return {"rule": rule, "type": "windows", "explanation": "添加Windows防火墙规则"}
    elif 'set allprofiles' in rule:
        return {"rule": rule, "type": "windows", "explanation": "设置Windows防火墙全局策略"}
    elif 'reset' in rule:
        return {"rule": rule, "type": "windows", "explanation": "重置Windows防火墙"}
    elif 'show' in rule:
        return {"rule": rule, "type": "windows", "explanation": "显示Windows防火墙配置"}
    return {"rule": rule, "type": "windows", "explanation": "Windows防火墙命令"}


def analyze_rules(rules_text: str) -> dict:
    """分析一组防火墙规则"""
    lines = rules_text.strip().split('\n')
    analyzed = []
    stats = {"total": 0, "accept": 0, "drop": 0, "reject": 0, "log": 0, "other": 0}

    for line in lines:
        result = explain_rule(line)
        analyzed.append(result)
        stats["total"] += 1
        if result.get("type") == "iptables":
            target = result.get("details", {}).get("target", "")
            if target == "ACCEPT":
                stats["accept"] += 1
            elif target == "DROP":
                stats["drop"] += 1
            elif target == "REJECT":
                stats["reject"] += 1
            elif target == "LOG":
                stats["log"] += 1
            else:
                stats["other"] += 1

    # 安全评估
    issues = []
    if stats["drop"] == 0 and stats["reject"] == 0:
        issues.append("没有DROP/REJECT规则，所有流量可能被允许")
    has_established = any("ESTABLISHED" in line for line in lines)
    if not has_established:
        issues.append("建议添加ESTABLISHED,RELATED状态规则")
    has_loopback = any("lo " in line or "-i lo" in line for line in lines)
    if not has_loopback:
        issues.append("建议允许回环接口(lo)")

    return {
        "success": True,
        "rules": analyzed,
        "stats": stats,
        "issues": issues,
        "security_score": max(0, 100 - len(issues) * 20)
    }
