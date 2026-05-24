"""服务器基础配置模块 - 用户管理、SSH加固、服务管理、文件权限、网络配置、日志审计、系统加固"""


def user_management(action: str, config: dict = None) -> dict:
    """用户与组管理命令生成"""
    config = config or {}
    username = config.get("username", "newuser")
    password = config.get("password", "P@ssw0rd123")
    groupname = config.get("groupname", "newgroup")
    shell = config.get("shell", "/bin/bash")
    home = config.get("home", f"/home/{username}")

    actions = {
        "create": {
            "name": "创建用户",
            "commands": [
                f"useradd -m -s {shell} -d {home} {username}",
                f"echo '{password}' | passwd --stdin {username}" if True else f"passwd {username}",
                f"echo '用户 {username} 创建完成，家目录: {home}'",
            ],
            "tips": ["-m 自动创建家目录", "-s 指定登录shell", "-d 指定家目录路径"]
        },
        "create-group": {
            "name": "创建组并添加用户",
            "commands": [
                f"groupadd {groupname}",
                f"usermod -aG {groupname} {username}",
                f"id {username}",
                f"echo '用户 {username} 已加入组 {groupname}'",
            ],
            "tips": ["-aG 追加到附加组（不覆盖原有组）", "用 id 命令验证组成员关系"]
        },
        "delete": {
            "name": "删除用户",
            "commands": [
                f"userdel -r {username}",
                f"echo '用户 {username} 及其家目录已删除'",
            ],
            "tips": ["-r 同时删除家目录和邮件", "先 kill 该用户所有进程: pkill -u {username}"]
        },
        "lock": {
            "name": "锁定账户",
            "commands": [
                f"passwd -l {username}",
                f"echo '账户 {username} 已锁定'",
            ],
            "tips": ["-l 锁定密码（在密码前加!!）", "解锁用 passwd -u {username}"]
        },
        "unlock": {
            "name": "解锁账户",
            "commands": [
                f"passwd -u {username}",
                f"echo '账户 {username} 已解锁'",
            ],
        },
        "password-policy": {
            "name": "设置密码策略",
            "commands": [
                f"chage -M 90 -m 7 -W 14 {username}",
                f"chage -l {username}",
                f"echo '密码策略: 最大有效期90天, 最短7天, 提前14天警告'",
            ],
            "tips": ["-M 最大天数", "-m 最小天数", "-W 提前警告天数", "-E 设置账户过期日期: chage -E 2026-12-31 {username}"]
        },
        "list": {
            "name": "查看用户信息",
            "commands": [
                f"id {username}",
                f"grep {username} /etc/passwd",
                f"last {username}",
                f"echo '---密码策略---'",
                f"chage -l {username}",
            ],
        },
        "list-all": {
            "name": "查看所有用户",
            "commands": [
                "cat /etc/passwd | grep -v nologin | grep -v /bin/false",
                "echo '---有登录shell的用户---'",
                "awk -F: '$7 !~ /nologin|false/ {print $1, $3, $6, $7}' /etc/passwd",
            ],
        },
    }

    if action not in actions:
        return {"success": False, "error": f"未知操作: {action}，可用: {list(actions.keys())}"}

    result = actions[action]
    return {
        "success": True,
        "action": action,
        "name": result["name"],
        "commands": result["commands"],
        "tips": result.get("tips", []),
    }


def ssh_hardening(config: dict = None) -> dict:
    """SSH安全加固配置生成"""
    config = config or {}
    port = config.get("port", "22")
    allow_users = config.get("allow_users", "")
    max_auth_tries = config.get("max_auth_tries", "3")

    sshd_config = f"""# ===== SSH 安全加固配置 =====
# 配置文件: /etc/ssh/sshd_config
# 修改后执行: systemctl restart sshd

# 修改默认端口
Port {port}

# 禁止root直接登录
PermitRootLogin no

# 禁用密码认证（仅允许密钥登录）
PasswordAuthentication no

# 限制最大认证尝试次数
MaxAuthTries {max_auth_tries}

# 空密码禁止登录
PermitEmptyPasswords no

# 启用公钥认证
PubkeyAuthentication yes

# 设置会话超时（300秒无活动断开）
ClientAliveInterval 300
ClientAliveCountMax 3

# 禁用X11转发
X11Forwarding no

# 禁用TCP转发（按需开启）
# AllowTcpForwarding no

# 限制登录用户（取消注释并填入用户名）
# AllowUsers {allow_users if allow_users else 'user1 user2'}

# 限制登录组
# AllowGroups sshusers

# 登录Banner
Banner /etc/issue.net

# 日志级别
LogLevel VERBOSE"""

    commands = [
        "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
        f"# 修改 /etc/ssh/sshd_config，将上述配置写入",
        f"sed -i 's/^#Port .*/Port {port}/' /etc/ssh/sshd_config",
        "sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
        "systemctl restart sshd",
        "ss -tlnp | grep sshd",
    ]

    return {
        "success": True,
        "name": "SSH安全加固",
        "config_content": sshd_config,
        "commands": commands,
        "tips": [
            "修改前务必备份: cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            "密钥认证需先部署公钥: ssh-copy-id user@host",
            "修改端口后记得开放防火墙: firewall-cmd --add-port={port}/tcp --permanent",
            "测试新配置前不要关闭当前SSH会话",
        ]
    }


def service_management(action: str, config: dict = None) -> dict:
    """服务管理命令生成"""
    config = config or {}
    service = config.get("service", "httpd")

    # 常见危险/不需要的服务列表
    dangerous_services = [
        "telnet.socket", "rsh.socket", "rlogin.socket", "rexec.socket",
        "tftp.socket", "vsftpd", "rpcbind", "nfs-server",
        "avahi-daemon", "cups", "postfix",
    ]

    actions = {
        "status": {
            "name": "查看服务状态",
            "commands": [
                f"systemctl status {service}",
                f"systemctl is-enabled {service}",
            ],
        },
        "enable": {
            "name": "启用服务（开机自启）",
            "commands": [
                f"systemctl enable {service}",
                f"systemctl start {service}",
                f"systemctl status {service}",
            ],
        },
        "disable": {
            "name": "禁用服务（禁止开机自启）",
            "commands": [
                f"systemctl stop {service}",
                f"systemctl disable {service}",
                f"echo '服务 {service} 已禁用'",
            ],
        },
        "restart": {
            "name": "重启服务",
            "commands": [
                f"systemctl restart {service}",
                f"systemctl status {service}",
            ],
        },
        "list-all": {
            "name": "查看所有服务状态",
            "commands": [
                "systemctl list-unit-files --type=service --state=enabled",
                "echo '---运行中的服务---'",
                "systemctl list-units --type=service --state=running",
            ],
        },
        "list-ports": {
            "name": "查看监听端口",
            "commands": [
                "ss -tlnp",
                "echo '---UDP端口---'",
                "ss -ulnp",
            ],
            "tips": ["ss 替代了 netstat，速度更快", "-t TCP  -u UDP  -l 监听  -n 数字显示  -p 显示进程"]
        },
        "disable-dangerous": {
            "name": "禁用常见危险服务",
            "commands": [
                f"# 以下为常见不需要的服务，按需选择禁用",
                *[f"systemctl disable --now {s} 2>/dev/null; echo '{s} 已禁用'" for s in dangerous_services],
                "echo '---请检查是否影响业务---'",
            ],
            "tips": ["禁用前确认业务不依赖这些服务", "telnet/rsh/rexec 使用明文传输，应改用SSH", "rpcbind/nfs 如不提供NFS服务应禁用"]
        },
    }

    if action not in actions:
        return {"success": False, "error": f"未知操作: {action}，可用: {list(actions.keys())}"}

    result = actions[action]
    return {
        "success": True,
        "action": action,
        "name": result["name"],
        "commands": result["commands"],
        "tips": result.get("tips", []),
    }


def file_permissions(action: str, config: dict = None) -> dict:
    """文件权限管理命令生成"""
    config = config or {}
    path = config.get("path", "/var/www/html")
    mode = config.get("mode", "755")
    user = config.get("user", "www-data")
    group = config.get("group", "www-data")
    acl_user = config.get("acl_user", "deploy")
    acl_perms = config.get("acl_perms", "rwx")

    actions = {
        "chmod": {
            "name": "修改文件权限",
            "commands": [
                f"chmod {mode} {path}",
                f"ls -la {path}",
            ],
            "tips": ["r=4 w=2 x=1", "755 = rwxr-xr-x（所有者全权限，组和其他读+执行）", "644 = rw-r--r--（文件常用）", "700 = rwx------（仅所有者）"]
        },
        "chown": {
            "name": "修改文件所有者",
            "commands": [
                f"chown {user}:{group} {path}",
                f"chown -R {user}:{group} {path}",
                f"ls -la {path}",
            ],
            "tips": ["-R 递归修改", "格式: chown 用户:组 文件"]
        },
        "find-suid": {
            "name": "查找SUID文件（提权风险）",
            "commands": [
                "find / -perm -4000 -type f 2>/dev/null",
                "echo '---SUID文件列表---'",
                "find / -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null",
            ],
            "tips": ["SUID文件以文件所有者权限运行，可能被利用提权", "非必要的SUID应去除: chmod u-s /path/to/file"]
        },
        "find-sgid": {
            "name": "查找SGID文件",
            "commands": [
                "find / -perm -2000 -type f 2>/dev/null",
            ],
        },
        "find-world-writable": {
            "name": "查找全局可写文件",
            "commands": [
                "find / -perm -o+w -type f 2>/dev/null",
                "echo '---全局可写目录---'",
                "find / -perm -o+w -type d 2>/dev/null",
            ],
            "tips": ["全局可写文件可能被任意修改", "修复: chmod o-w /path/to/file"]
        },
        "acl-set": {
            "name": "设置ACL权限",
            "commands": [
                f"setfacl -m u:{acl_user}:{acl_perms} {path}",
                f"getfacl {path}",
            ],
            "tips": ["ACL提供更精细的权限控制", "-m 修改  -x 删除  -b 清除所有ACL", "需要文件系统支持ACL（ext4默认支持）"]
        },
        "acl-show": {
            "name": "查看ACL权限",
            "commands": [
                f"getfacl {path}",
            ],
        },
        "umask": {
            "name": "设置默认umask",
            "commands": [
                "umask 027",
                "echo 'umask 027' >> /etc/profile",
                "echo '新文件默认权限: 640, 新目录默认权限: 750'",
            ],
            "tips": ["umask 022 → 文件644, 目录755", "umask 027 → 文件640, 目录755（更安全）", "umask 077 → 文件600, 目录700（最严格）"]
        },
    }

    if action not in actions:
        return {"success": False, "error": f"未知操作: {action}，可用: {list(actions.keys())}"}

    result = actions[action]
    return {
        "success": True,
        "action": action,
        "name": result["name"],
        "commands": result["commands"],
        "tips": result.get("tips", []),
    }


def network_config(action: str, config: dict = None) -> dict:
    """网络配置命令生成"""
    config = config or {}
    connection = config.get("connection", "ens33")
    ip = config.get("ip", "192.168.1.100")
    mask = config.get("mask", "24")
    gateway = config.get("gateway", "192.168.1.1")
    dns = config.get("dns", "8.8.8.8")
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
            ],
        },
        "static-ip": {
            "name": "配置静态IP地址",
            "commands": [
                f"nmcli con mod {connection} ipv4.addresses {ip}/{mask}",
                f"nmcli con mod {connection} ipv4.gateway {gateway}",
                f"nmcli con mod {connection} ipv4.dns {dns}",
                f"nmcli con mod {connection} ipv4.method manual",
                f"nmcli con up {connection}",
                "ip addr show",
            ],
            "tips": ["先用 nmcli con show 查看连接名", "connection 名称通常是网卡名或连接名", "修改后需 nmcli con up 生效"]
        },
        "dns": {
            "name": "配置DNS",
            "commands": [
                f"echo 'nameserver {dns}' > /etc/resolv.conf",
                f"echo 'nameserver 8.8.4.4' >> /etc/resolv.conf",
                "cat /etc/resolv.conf",
                "nslookup baidu.com",
            ],
        },
        "hosts": {
            "name": "配置hosts文件",
            "commands": [
                f"echo '{ip} {hostname}' >> /etc/hosts",
                "cat /etc/hosts",
            ],
        },
        "hostname": {
            "name": "修改主机名",
            "commands": [
                f"hostnamectl set-hostname {hostname}",
                "hostnamectl",
            ],
        },
        "route-add": {
            "name": "添加静态路由",
            "commands": [
                f"ip route add {network} via {route_gw}",
                "ip route show",
            ],
            "tips": ["永久生效需写入配置文件", "CentOS: /etc/sysconfig/network-scripts/route-{connection}"]
        },
        "route-show": {
            "name": "查看路由表",
            "commands": [
                "ip route show",
                "echo '---策略路由---'",
                "ip rule show",
            ],
        },
        "firewall-cmd": {
            "name": "firewalld基本操作",
            "commands": [
                "firewall-cmd --state",
                "firewall-cmd --list-all",
                "firewall-cmd --list-ports",
                f"firewall-cmd --add-port=80/tcp --permanent",
                "firewall-cmd --reload",
            ],
            "tips": ["--permanent 永久生效", "修改后必须 --reload", "查看所有区域: firewall-cmd --get-zones"]
        },
    }

    if action not in actions:
        return {"success": False, "error": f"未知操作: {action}，可用: {list(actions.keys())}"}

    result = actions[action]
    return {
        "success": True,
        "action": action,
        "name": result["name"],
        "commands": result["commands"],
        "tips": result.get("tips", []),
    }


def log_audit(action: str, config: dict = None) -> dict:
    """日志审计配置"""
    config = config or {}
    remote_ip = config.get("remote_ip", "192.168.1.200")
    username = config.get("username", "root")

    actions = {
        "system-log": {
            "name": "查看系统日志",
            "commands": [
                "journalctl -xe --no-pager | tail -50",
                "echo '---最近登录---'",
                "last -20",
                "echo '---失败登录---'",
                "lastb -20",
            ],
        },
        "auth-log": {
            "name": "查看认证日志",
            "commands": [
                "journalctl -u sshd --no-pager | tail -30",
                "echo '---sudo操作---'",
                "grep sudo /var/log/secure | tail -20",
                "echo '---当前登录用户---'",
                "who",
            ],
        },
        "remote-log": {
            "name": "配置远程日志服务器",
            "commands": [
                f"echo '*.* @{remote_ip}:514' >> /etc/rsyslog.conf",
                "systemctl restart rsyslog",
                "echo '---验证发送---'",
                "logger 'test remote log message'",
            ],
            "tips": ["@ 表示UDP传输，@@ 表示TCP", "远程服务器需配置接收: $ModLoad imudp / $UDPServerRun 514"]
        },
        "audit-user": {
            "name": "审计指定用户操作",
            "commands": [
                f"journalctl _UID=$(id -u {username}) --no-pager | tail -50",
                f"grep {username} /var/log/secure | tail -30",
                f"last {username}",
            ],
        },
        "log-rotate": {
            "name": "日志轮转配置",
            "commands": [
                "cat /etc/logrotate.conf",
                "echo '---查看轮转状态---'",
                "ls -la /var/log/*.gz",
            ],
            "tips": ["默认配置: /etc/logrotate.conf", "应用配置: /etc/logrotate.d/"]
        },
    }

    if action not in actions:
        return {"success": False, "error": f"未知操作: {action}，可用: {list(actions.keys())}"}

    result = actions[action]
    return {
        "success": True,
        "action": action,
        "name": result["name"],
        "commands": result["commands"],
        "tips": result.get("tips", []),
    }


def system_hardening(action: str, config: dict = None) -> dict:
    """系统安全加固"""
    config = config or {}

    actions = {
        "selinux": {
            "name": "SELinux配置",
            "commands": [
                "getenforce",
                "setenforce 1",
                "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                "cat /etc/selinux/config | grep SELINUX=",
            ],
            "tips": ["enforcing=强制  permissive=宽容  disabled=禁用", "修改 /etc/selinux/config 需重启生效"]
        },
        "hosts-allow-deny": {
            "name": "配置TCP Wrappers",
            "commands": [
                "echo 'sshd: 192.168.1.0/24' >> /etc/hosts.allow",
                "echo 'sshd: ALL' >> /etc/hosts.deny",
                "echo '---允许规则---'",
                "cat /etc/hosts.allow",
                "echo '---拒绝规则---'",
                "cat /etc/hosts.deny",
            ],
            "tips": ["hosts.allow 优先于 hosts.deny", "格式: 服务: 来源", "支持通配符和网段"]
        },
        "banner": {
            "name": "设置登录Banner",
            "commands": [
                "echo 'Authorized users only. All activity may be monitored.' > /etc/issue",
                "cp /etc/issue /etc/issue.net",
                "echo '---SSH Banner---'",
                "echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config",
                "systemctl restart sshd",
            ],
        },
        "cron-restrict": {
            "name": "限制cron使用",
            "commands": [
                "echo 'root' > /etc/cron.allow",
                "chmod 600 /etc/cron.allow",
                "echo '---允许使用cron的用户---'",
                "cat /etc/cron.allow",
            ],
            "tips": ["cron.allow 存在时只允许列表中的用户", "cron.deny 仅在 cron.allow 不存在时生效"]
        },
        "sysctl": {
            "name": "内核参数加固",
            "commands": [
                "cat >> /etc/sysctl.conf << 'EOF'",
                "# 禁止响应ping",
                "net.ipv4.icmp_echo_ignore_all = 1",
                "# 开启SYN Cookie防护",
                "net.ipv4.tcp_syncookies = 1",
                "# 禁止IP源路由",
                "net.ipv4.conf.all.accept_source_route = 0",
                "# 禁止ICMP重定向",
                "net.ipv4.conf.all.accept_redirects = 0",
                "# 开启反向路径过滤",
                "net.ipv4.conf.all.rp_filter = 1",
                "# 记录异常数据包",
                "net.ipv4.conf.all.log_martians = 1",
                "EOF",
                "sysctl -p",
            ],
            "tips": ["sysctl -p 重新加载配置", "icmp_echo_ignore_all=1 禁ping（注意监控可能需要ping）"]
        },
        "check-open-ports": {
            "name": "检查开放端口",
            "commands": [
                "ss -tlnp",
                "echo '---UDP监听---'",
                "ss -ulnp",
                "echo '---防火墙规则---'",
                "iptables -L -n --line-numbers",
            ],
        },
        "password-policy-global": {
            "name": "全局密码策略",
            "commands": [
                "cat >> /etc/security/pwquality.conf << 'EOF'",
                "minlen = 8",
                "dcredit = -1",
                "ucredit = -1",
                "lcredit = -1",
                "ocredit = -1",
                "EOF",
                "echo '密码策略: 最少8位, 包含大小写字母、数字、特殊字符各至少1个'",
            ],
            "tips": ["dcredit 数字  ucredit 大写  lcredit 小写  ocredit 特殊字符", "-1 表示至少需要1个"]
        },
    }

    if action not in actions:
        return {"success": False, "error": f"未知操作: {action}，可用: {list(actions.keys())}"}

    result = actions[action]
    return {
        "success": True,
        "action": action,
        "name": result["name"],
        "commands": result["commands"],
        "tips": result.get("tips", []),
    }


def competition_server_task(task_num: int, config: dict = None) -> dict:
    """竞赛服务器配置题目模板"""
    config = config or {}
    username = config.get("username", "newuser")
    password = config.get("password", "P@ssw0rd123")
    port = config.get("port", "2222")
    ip = config.get("ip", "192.168.1.100")
    service = config.get("service", "httpd")

    tasks = {
        1: {
            "name": "用户创建与权限配置",
            "description": f"创建用户 {username}，设置密码，加入 wheel 组，配置密码90天过期",
            "variables": {"username": "用户名", "password": "密码"},
            "commands": [
                f"useradd -m -s /bin/bash {username}",
                f"echo '{password}' | passwd --stdin {username}",
                f"usermod -aG wheel {username}",
                f"chage -M 90 -m 7 -W 14 {username}",
                f"id {username}",
                f"chage -l {username}",
            ],
            "tips": ["wheel组成员可使用sudo", "chage -M 设置密码最大有效期"],
        },
        2: {
            "name": "SSH安全加固",
            "description": f"修改SSH端口为 {port}，禁止root登录，禁止密码认证，仅允许密钥登录",
            "variables": {"port": "SSH端口号"},
            "commands": [
                "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
                f"sed -i 's/^#Port .*/Port {port}/' /etc/ssh/sshd_config",
                "sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                "sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
                f"firewall-cmd --add-port={port}/tcp --permanent",
                "firewall-cmd --reload",
                "systemctl restart sshd",
                "ss -tlnp | grep sshd",
            ],
            "tips": ["务必先部署密钥再禁用密码登录", "修改端口后记得开防火墙", "测试前不要关闭当前会话"],
        },
        3: {
            "name": "服务管理与端口安全",
            "description": f"禁用不必要的服务，确保 {service} 服务运行，检查监听端口",
            "variables": {"service": "需要保持运行的服务名"},
            "commands": [
                "systemctl list-unit-files --type=service --state=enabled",
                "# 禁用危险服务",
                "systemctl disable --now telnet.socket 2>/dev/null",
                "systemctl disable --now rsh.socket 2>/dev/null",
                "systemctl disable --now rpcbind 2>/dev/null",
                f"# 确保 {service} 运行",
                f"systemctl enable {service}",
                f"systemctl start {service}",
                f"systemctl status {service}",
                "echo '---当前监听端口---'",
                "ss -tlnp",
            ],
            "tips": ["禁用服务前确认业务不依赖", "用 ss -tlnp 检查所有监听端口"],
        },
        4: {
            "name": "文件权限与SUID清理",
            "description": "查找并清理危险的SUID文件，设置关键目录权限，配置umask",
            "variables": {},
            "commands": [
                "echo '---查找SUID文件---'",
                "find / -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null",
                "echo '---查找全局可写文件---'",
                "find / -perm -o+w -type f 2>/dev/null",
                "echo '---设置umask---'",
                "echo 'umask 027' >> /etc/profile",
                "umask 027",
                "echo '---设置关键目录权限---'",
                "chmod 700 /root",
                "chmod 600 /etc/shadow",
                "chmod 644 /etc/passwd",
            ],
            "tips": ["SUID文件以所有者权限运行，可能被提权利用", "umask 027 → 新文件640, 新目录755"],
        },
        5: {
            "name": "系统加固综合",
            "description": "SELinux开启、内核参数加固、登录Banner、TCP Wrappers、密码策略",
            "variables": {},
            "commands": [
                "# 1. SELinux",
                "setenforce 1",
                "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                "# 2. 内核参数",
                "cat >> /etc/sysctl.conf << 'EOF'",
                "net.ipv4.icmp_echo_ignore_all = 1",
                "net.ipv4.tcp_syncookies = 1",
                "net.ipv4.conf.all.accept_source_route = 0",
                "net.ipv4.conf.all.accept_redirects = 0",
                "EOF",
                "sysctl -p",
                "# 3. Banner",
                "echo 'Authorized users only.' > /etc/issue",
                "cp /etc/issue /etc/issue.net",
                "# 4. TCP Wrappers",
                "echo 'sshd: 192.168.1.0/24' >> /etc/hosts.allow",
                "echo 'sshd: ALL' >> /etc/hosts.deny",
                "# 5. 密码策略",
                "echo 'minlen = 8' >> /etc/security/pwquality.conf",
                "echo 'dcredit = -1' >> /etc/security/pwquality.conf",
                "echo 'ucredit = -1' >> /etc/security/pwquality.conf",
            ],
            "tips": ["SELinux修改需重启永久生效", "sysctl -p 加载内核参数", "hosts.allow优先于hosts.deny"],
        },
    }

    if task_num not in tasks:
        return {"success": False, "error": f"未知题号: {task_num}，可用: {list(tasks.keys())}"}

    task = tasks[task_num]
    return {
        "success": True,
        "task_num": task_num,
        "name": task["name"],
        "description": task["description"],
        "variables": task["variables"],
        "commands": task["commands"],
        "tips": task["tips"],
    }


def list_server_scenarios() -> dict:
    """列出所有可用场景"""
    return {
        "success": True,
        "scenarios": {
            "user": {"name": "用户与组管理", "actions": ["create", "create-group", "delete", "lock", "unlock", "password-policy", "list", "list-all"]},
            "ssh": {"name": "SSH安全加固", "actions": ["hardening"]},
            "service": {"name": "服务管理", "actions": ["status", "enable", "disable", "restart", "list-all", "list-ports", "disable-dangerous"]},
            "permissions": {"name": "文件权限", "actions": ["chmod", "chown", "find-suid", "find-sgid", "find-world-writable", "acl-set", "acl-show", "umask"]},
            "network": {"name": "网络配置", "actions": ["show", "static-ip", "dns", "hosts", "hostname", "route-add", "route-show", "firewall-cmd"]},
            "log": {"name": "日志审计", "actions": ["system-log", "auth-log", "remote-log", "audit-user", "log-rotate"]},
            "hardening": {"name": "系统加固", "actions": ["selinux", "hosts-allow-deny", "banner", "cron-restrict", "sysctl", "check-open-ports", "password-policy-global"]},
        },
        "competition_tasks": [1, 2, 3, 4, 5],
    }
