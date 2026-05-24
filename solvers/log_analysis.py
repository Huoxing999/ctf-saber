"""日志分析模块 - Web日志、系统日志、安全事件分析"""
import re
import json
from collections import Counter, defaultdict
from datetime import datetime
from solvers.common import find_flags_in_text


def analyze_web_log(log_text: str) -> dict:
    """分析Web访问日志（Apache/Nginx通用格式）"""
    lines = log_text.strip().split('\n')
    total = len(lines)

    # 解析日志行
    # 常见格式: IP - - [time] "METHOD URL PROTO" STATUS SIZE "REF" "UA"
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'.*?\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<url>\S+)\s+\S+"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+|-)'
        r'(?:\s+"(?P<referrer>[^"]*)")?'
        r'(?:\s+"(?P<ua>[^"]*)")?'
    )

    parsed = []
    parse_errors = 0
    for line in lines:
        m = log_pattern.match(line.strip())
        if m:
            parsed.append(m.groupdict())
        else:
            parse_errors += 1

    if not parsed:
        # 尝试简化匹配
        return _analyze_log_simple(log_text)

    # 统计分析
    ip_counter = Counter(r['ip'] for r in parsed)
    url_counter = Counter(r['url'] for r in parsed)
    status_counter = Counter(r['status'] for r in parsed)
    method_counter = Counter(r['method'] for r in parsed)

    # 安全事件检测
    security_events = []

    # SQL注入检测
    sqli_patterns = [
        r"(?i)(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*')",
        r"(?i)(select\s+.*\s+from|insert\s+into|drop\s+table|update\s+.*\s+set)",
        r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    ]
    for r in parsed:
        for pat in sqli_patterns:
            if re.search(pat, r['url']):
                security_events.append({
                    "type": "SQL注入疑似",
                    "ip": r['ip'],
                    "url": r['url'][:200],
                    "time": r['time'],
                    "severity": "高"
                })
                break

    # XSS检测
    xss_patterns = [r'<script', r'onerror\s*=', r'onload\s*=', r'javascript:']
    for r in parsed:
        for pat in xss_patterns:
            if re.search(pat, r['url'], re.IGNORECASE):
                security_events.append({
                    "type": "XSS疑似",
                    "ip": r['ip'],
                    "url": r['url'][:200],
                    "time": r['time'],
                    "severity": "中"
                })
                break

    # 目录遍历检测
    traversal_patterns = [r'\.\./', r'\.\.\\', r'%2e%2e', r'etc/passwd', r'win\.ini']
    for r in parsed:
        for pat in traversal_patterns:
            if re.search(pat, r['url'], re.IGNORECASE):
                security_events.append({
                    "type": "目录遍历疑似",
                    "ip": r['ip'],
                    "url": r['url'][:200],
                    "time": r['time'],
                    "severity": "高"
                })
                break

    # 扫描器检测（大量404）
    ip_404 = Counter()
    for r in parsed:
        if r['status'] == '404':
            ip_404[r['ip']] += 1
    for ip, count in ip_404.most_common(5):
        if count > 20:
            security_events.append({
                "type": "目录扫描疑似",
                "ip": ip,
                "count_404": count,
                "severity": "中"
            })

    # 暴力破解检测（大量401/403）
    ip_auth_fail = Counter()
    for r in parsed:
        if r['status'] in ('401', '403'):
            ip_auth_fail[r['ip']] += 1
    for ip, count in ip_auth_fail.most_common(5):
        if count > 10:
            security_events.append({
                "type": "暴力破解疑似",
                "ip": ip,
                "count_fail": count,
                "severity": "高"
            })

    # CC攻击检测（单IP高频请求）
    ip_total = Counter(r['ip'] for r in parsed)
    avg_req = total / max(len(ip_total), 1)
    for ip, count in ip_total.most_common(5):
        if count > avg_req * 5:
            security_events.append({
                "type": "CC攻击疑似",
                "ip": ip,
                "request_count": count,
                "severity": "高"
            })

    # Webshell检测
    webshell_patterns = [r'\.php\?.*cmd', r'\.asp\?.*exec', r'eval\s*\(', r'base64_decode']
    for r in parsed:
        for pat in webshell_patterns:
            if re.search(pat, r['url'], re.IGNORECASE):
                security_events.append({
                    "type": "Webshell疑似",
                    "ip": r['ip'],
                    "url": r['url'][:200],
                    "time": r['time'],
                    "severity": "极高"
                })
                break

    # Flag搜索
    flags = find_flags_in_text(log_text)

    # 提取User-Agent中的异常
    ua_counter = Counter(r.get('ua', '') for r in parsed if r.get('ua'))
    suspicious_ua = []
    tool_keywords = ['sqlmap', 'nmap', 'nikto', 'burp', 'dirbuster', 'gobuster', 'hydra', 'wfuzz']
    for ua, count in ua_counter.items():
        for kw in tool_keywords:
            if kw.lower() in ua.lower():
                suspicious_ua.append({"ua": ua[:100], "count": count, "tool": kw})

    return {
        "success": True,
        "total_lines": total,
        "parsed_lines": len(parsed),
        "parse_errors": parse_errors,
        "top_ips": ip_counter.most_common(10),
        "top_urls": url_counter.most_common(10),
        "status_distribution": dict(status_counter),
        "method_distribution": dict(method_counter),
        "security_events": security_events[:50],
        "suspicious_ua": suspicious_ua,
        "flags": flags
    }


def _analyze_log_simple(log_text: str) -> dict:
    """简化的日志分析（当标准格式解析失败时）"""
    lines = log_text.strip().split('\n')

    # 提取所有IP
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    all_ips = []
    for line in lines:
        all_ips.extend(ip_pattern.findall(line))

    ip_counter = Counter(all_ips)

    # 提取所有URL
    url_pattern = re.compile(r'(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)')
    all_urls = []
    for line in lines:
        m = url_pattern.search(line)
        if m:
            all_urls.append(m.group(1))

    url_counter = Counter(all_urls)

    # 提取HTTP状态码
    status_pattern = re.compile(r'\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s')
    all_status = []
    for line in lines:
        m = status_pattern.search(line)
        if m:
            all_status.append(m.group(1))

    status_counter = Counter(all_status)

    flags = find_flags_in_text(log_text)

    return {
        "success": True,
        "total_lines": len(lines),
        "mode": "简化分析",
        "top_ips": ip_counter.most_common(10),
        "top_urls": url_counter.most_common(10),
        "status_distribution": dict(status_counter),
        "flags": flags
    }


def analyze_auth_log(log_text: str) -> dict:
    """分析系统认证日志（Linux auth.log / secure）"""
    lines = log_text.strip().split('\n')

    events = {
        "ssh_login_success": [],
        "ssh_login_fail": [],
        "sudo_usage": [],
        "su_usage": [],
        "user_add": [],
        "crontab": [],
    }

    for line in lines:
        # SSH登录成功
        if 'Accepted' in line and 'ssh' in line.lower():
            m = re.search(r'Accepted \w+ for (\S+) from (\S+)', line)
            if m:
                events["ssh_login_success"].append({"user": m.group(1), "ip": m.group(2)})

        # SSH登录失败
        if 'Failed password' in line:
            m = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
            if m:
                events["ssh_login_fail"].append({"user": m.group(1), "ip": m.group(2)})

        # sudo使用
        if 'sudo:' in line:
            events["sudo_usage"].append(line.strip()[:200])

        # su切换
        if 'su:' in line and 'session opened' in line:
            events["su_usage"].append(line.strip()[:200])

        # 用户添加
        if 'useradd' in line or 'adduser' in line:
            events["user_add"].append(line.strip()[:200])

        # crontab修改
        if 'CRON' in line or 'crontab' in line:
            events["crontab"].append(line.strip()[:200])

    # 暴力破解检测
    fail_counter = Counter((e['user'], e['ip']) for e in events["ssh_login_fail"])
    brute_force = []
    for (user, ip), count in fail_counter.most_common(10):
        if count > 5:
            brute_force.append({"user": user, "ip": ip, "fail_count": count})

    flags = find_flags_in_text(log_text)

    return {
        "success": True,
        "total_lines": len(lines),
        "events": {k: len(v) for k, v in events.items()},
        "details": {k: v[:20] for k, v in events.items()},
        "brute_force_suspects": brute_force,
        "flags": flags
    }


def analyze_windows_log(log_text: str) -> dict:
    """分析Windows事件日志（导出的文本格式）"""
    lines = log_text.strip().split('\n')

    event_types = {
        "登录成功": [],
        "登录失败": [],
        "账户创建": [],
        "权限提升": [],
        "进程创建": [],
        "文件访问": [],
    }

    # 事件ID映射
    event_id_map = {
        '4624': '登录成功',
        '4625': '登录失败',
        '4720': '账户创建',
        '4672': '权限提升',
        '4688': '进程创建',
        '4663': '文件访问',
    }

    for line in lines:
        # 搜索事件ID
        for eid, name in event_id_map.items():
            if f'EventID={eid}' in line or f'Event ID: {eid}' in line:
                event_types[name].append(line.strip()[:200])
                break

    flags = find_flags_in_text(log_text)

    return {
        "success": True,
        "total_lines": len(lines),
        "event_summary": {k: len(v) for k, v in event_types.items()},
        "details": {k: v[:10] for k, v in event_types.items() if v},
        "flags": flags
    }


def parse_json_log(log_text: str) -> dict:
    """解析JSON格式日志（如Elasticsearch导出）"""
    lines = log_text.strip().split('\n')
    records = []
    parse_errors = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            parse_errors += 1

    if not records:
        return {"success": False, "error": "无法解析JSON日志", "parse_errors": parse_errors}

    # 统计字段
    all_keys = Counter()
    for r in records:
        all_keys.update(r.keys())

    # 搜索敏感字段
    sensitive_fields = ['password', 'token', 'secret', 'key', 'auth', 'cookie', 'session']
    found_sensitive = []
    for r in records:
        for field in sensitive_fields:
            for k in r.keys():
                if field.lower() in k.lower():
                    found_sensitive.append({"field": k, "sample": str(r[k])[:100]})
                    break

    flags = find_flags_in_text(log_text)

    return {
        "success": True,
        "total_records": len(records),
        "parse_errors": parse_errors,
        "fields": dict(all_keys.most_common(20)),
        "sensitive_fields": found_sensitive[:20],
        "sample": records[:3],
        "flags": flags
    }
