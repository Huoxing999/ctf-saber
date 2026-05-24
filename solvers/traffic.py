"""流量分析模块 - pcap解析、敏感信息提取、隧道检测、USB键盘解析"""
import re
import struct
from solvers.common import find_flags_in_text, extract_strings


def analyze_pcap(filepath: str) -> dict:
    """分析pcap文件，提取关键信息"""
    results = {
        "protocols": {}, "conversations": [], "credentials": [],
        "flags": [], "http_requests": [], "dns_queries": [],
        "total_packets": 0, "anomalies": []
    }

    try:
        from scapy.all import rdpcap, TCP, UDP, DNS, Raw, IP, ICMP

        packets = rdpcap(filepath)
        results["total_packets"] = len(packets)

        protocol_count = {}
        conversations = {}
        icmp_data = b''

        for pkt in packets:
            # 协议统计
            if pkt.haslayer(TCP):
                protocol_count["TCP"] = protocol_count.get("TCP", 0) + 1
            if pkt.haslayer(UDP):
                protocol_count["UDP"] = protocol_count.get("UDP", 0) + 1
            if pkt.haslayer(DNS):
                protocol_count["DNS"] = protocol_count.get("DNS", 0) + 1
                if pkt[DNS].qr == 0:
                    for i in range(pkt[DNS].qdcount):
                        try:
                            qname = pkt[DNS].qd[i].qname.decode('utf-8', errors='ignore')
                            results["dns_queries"].append(qname)
                        except Exception:
                            pass
            if pkt.haslayer(ICMP):
                protocol_count["ICMP"] = protocol_count.get("ICMP", 0) + 1
                # ICMP隧道检测：收集ICMP数据
                if pkt.haslayer(Raw):
                    icmp_data += pkt[Raw].load

            # 会话跟踪
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                key = f"{src}:{sport} -> {dst}:{dport}"
                if key not in conversations:
                    conversations[key] = 0
                conversations[key] += 1

            # 提取TCP载荷
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load

                try:
                    text = payload.decode('utf-8', errors='ignore')
                    results["flags"].extend(find_flags_in_text(text))

                    # HTTP请求检测
                    if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                        lines = text.split('\r\n')
                        results["http_requests"].append(lines[0])

                        for line in lines:
                            if line.lower().startswith('authorization:'):
                                results["credentials"].append({"type": "Authorization", "value": line.split(':', 1)[1].strip()})
                            if line.lower().startswith('cookie:'):
                                results["credentials"].append({"type": "Cookie", "value": line.split(':', 1)[1].strip()})

                    # FTP凭据
                    if 'USER ' in text or 'PASS ' in text:
                        results["credentials"].append({"type": "FTP", "value": text.strip()})

                    # SMTP明文
                    if text.startswith(('EHLO', 'AUTH', 'MAIL FROM')):
                        results["credentials"].append({"type": "SMTP", "value": text[:200]})

                    # Telnet明文
                    if any(cmd in text for cmd in ['login:', 'Password:', 'password:']):
                        results["credentials"].append({"type": "Telnet", "value": text[:200]})

                    # Base64载荷
                    b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
                    for b64 in b64_matches[:5]:
                        try:
                            import base64
                            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                            if any(32 <= ord(c) < 127 for c in decoded):
                                results["credentials"].append({"type": "Base64 in payload", "original": b64[:50], "decoded": decoded[:100]})
                        except Exception:
                            pass
                except Exception:
                    pass

                # 搜索flag的hex形式
                hex_payload = payload.hex()
                if '666c6167' in hex_payload:
                    results["flags"].append("Found 'flag' hex in packet payload")

            # HTTP响应提取
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load
                try:
                    text = payload.decode('utf-8', errors='ignore')
                    if text.startswith('HTTP/'):
                        body = text.split('\r\n\r\n', 1)
                        if len(body) > 1:
                            results["flags"].extend(find_flags_in_text(body[1]))
                except Exception:
                    pass

        results["protocols"] = protocol_count
        results["flags"] = list(set(results["flags"]))

        # 填充会话信息
        for conn, count in sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:20]:
            results["conversations"].append({"connection": conn, "packets": count})

        # DNS隧道检测
        if results["dns_queries"]:
            long_domains = [q for q in results["dns_queries"] if len(q) > 50]
            if long_domains:
                results["anomalies"].append({
                    "type": "DNS隧道疑似",
                    "reason": f"发现{len(long_domains)}个超长域名查询",
                    "examples": long_domains[:3]
                })

        # ICMP隧道检测
        if len(icmp_data) > 100:
            icmp_strings = extract_strings(icmp_data, min_len=4)
            if icmp_strings:
                results["anomalies"].append({
                    "type": "ICMP隧道疑似",
                    "reason": f"ICMP载荷中发现{len(icmp_strings)}个可打印字符串",
                    "examples": icmp_strings[:5]
                })

    except ImportError:
        results["error"] = "scapy未安装，无法解析pcap。请运行: pip install scapy"
    except Exception as e:
        results["error"] = str(e)

    return results


def extract_strings_from_pcap(filepath: str) -> dict:
    """从pcap中提取所有可打印字符串"""
    with open(filepath, 'rb') as f:
        data = f.read()

    strings = extract_strings(data, min_len=6)
    flags = find_flags_in_text(''.join(strings))

    return {
        "total_strings": len(strings),
        "strings": strings[:200],
        "flags": list(set(flags))
    }


def parse_usb_keyboard(filepath: str) -> dict:
    """USB键盘流量解析（适用于USB HID数据）"""
    try:
        from scapy.all import rdpcap, Raw

        packets = rdpcap(filepath)

        # USB HID键码映射
        KEY_MAP = {
            0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e',
            0x09: 'f', 0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j',
            0x0e: 'k', 0x0f: 'l', 0x10: 'm', 0x11: 'n', 0x12: 'o',
            0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
            0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x', 0x1c: 'y',
            0x1d: 'z', 0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4',
            0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9',
            0x27: '0', 0x28: '\n', 0x29: '[ESC]', 0x2a: '[BACKSPACE]',
            0x2b: '\t', 0x2c: ' ', 0x2d: '-', 0x2e: '=', 0x2f: '[',
            0x30: ']', 0x31: '\\', 0x33: ';', 0x34: "'", 0x35: '`',
            0x36: ',', 0x37: '.', 0x38: '/',
        }

        SHIFT_MAP = {
            0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D', 0x08: 'E',
            0x09: 'F', 0x0a: 'G', 0x0b: 'H', 0x0c: 'I', 0x0d: 'J',
            0x0e: 'K', 0x0f: 'L', 0x10: 'M', 0x11: 'N', 0x12: 'O',
            0x13: 'P', 0x14: 'Q', 0x15: 'R', 0x16: 'S', 0x17: 'T',
            0x18: 'U', 0x19: 'V', 0x1a: 'W', 0x1b: 'X', 0x1c: 'Y',
            0x1d: 'Z', 0x1e: '!', 0x1f: '@', 0x20: '#', 0x21: '$',
            0x22: '%', 0x23: '^', 0x24: '&', 0x25: '*', 0x26: '(',
            0x27: ')', 0x2d: '_', 0x2e: '+', 0x2f: '{', 0x30: '}',
            0x31: '|', 0x33: ':', 0x34: '"', 0x35: '~', 0x36: '<',
            0x37: '>', 0x38: '?',
        }

        result_text = []
        raw_keys = []

        for pkt in packets:
            if pkt.haslayer(Raw):
                data = pkt[Raw].load
                if len(data) >= 8:
                    # USB HID数据格式: modifier, reserved, key1, key2, ...
                    modifier = data[0]
                    key_code = data[2]

                    if key_code == 0:
                        continue

                    shift = modifier & 0x22  # Left/Right Shift
                    ctrl = modifier & 0x11   # Left/Right Ctrl
                    alt = modifier & 0x44    # Left/Right Alt

                    if ctrl or alt:
                        mods = []
                        if ctrl:
                            mods.append("Ctrl")
                        if alt:
                            mods.append("Alt")
                        if shift:
                            mods.append("Shift")
                        key = KEY_MAP.get(key_code, f'[0x{key_code:02x}]')
                        result_text.append(f"[{'+'.join(mods)}+{key}]")
                        raw_keys.append({"modifier": modifier, "key": key_code, "display": f"[{'+'.join(mods)}+{key}]"})
                    elif shift and key_code in SHIFT_MAP:
                        result_text.append(SHIFT_MAP[key_code])
                        raw_keys.append({"modifier": modifier, "key": key_code, "display": SHIFT_MAP[key_code]})
                    elif key_code in KEY_MAP:
                        result_text.append(KEY_MAP[key_code])
                        raw_keys.append({"modifier": modifier, "key": key_code, "display": KEY_MAP[key_code]})

        typed_text = ''.join(result_text)
        flags = find_flags_in_text(typed_text)

        return {
            "success": True,
            "typed_text": typed_text,
            "flags": flags,
            "total_keys": len(raw_keys)
        }
    except ImportError:
        return {"success": False, "error": "scapy未安装，请运行: pip install scapy"}
    except Exception as e:
        return {"success": False, "error": str(e)}
