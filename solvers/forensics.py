"""电子数据取证模块 - 磁盘取证、内存取证、文件恢复、竞赛取证"""
import os
import re
import struct
import hashlib
import datetime
import json
from solvers.common import extract_strings, find_flags_in_text, find_flags_in_strings


def analyze_file_metadata(filepath: str) -> dict:
    """分析文件元数据（基础取证信息）"""
    stat = os.stat(filepath)

    with open(filepath, 'rb') as f:
        header = f.read(64)
        f.seek(-64, 2)
        tail = f.read()

    # 计算多种哈希
    with open(filepath, 'rb') as f:
        data = f.read()

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # 文件类型检测
    file_type = _detect_file_type(header)

    # 时间戳信息
    import datetime
    timestamps = {
        "创建时间": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "修改时间": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "访问时间": datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
    }

    # 提取字符串中的敏感信息
    strings = extract_strings(data, min_len=4)
    flags = find_flags_in_strings(strings)

    # 搜索可能的URL、IP、邮箱
    all_text = ' '.join(strings[:5000])
    urls = re.findall(r'https?://[^\s"\'<>]+', all_text)
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', all_text)
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_text)

    return {
        "success": True,
        "filename": os.path.basename(filepath),
        "file_size": stat.st_size,
        "file_type": file_type,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "timestamps": timestamps,
        "header_hex": header[:16].hex(),
        "tail_hex": tail[-16:].hex(),
        "urls_found": list(set(urls))[:20],
        "ips_found": list(set(ips))[:20],
        "emails_found": list(set(emails))[:20],
        "flags": flags,
        "string_count": len(strings)
    }


def _detect_file_type(header: bytes) -> str:
    """根据文件头检测文件类型"""
    signatures = {
        b'\xff\xd8\xff': "JPEG图片",
        b'\x89PNG': "PNG图片",
        b'GIF8': "GIF图片",
        b'PK\x03\x04': "ZIP压缩包/Office文档",
        b'Rar!\x1a\x07': "RAR压缩包",
        b'\x7fELF': "ELF可执行文件",
        b'MZ': "PE可执行文件",
        b'%PDF': "PDF文档",
        b'\xd0\xcf\x11\xe0': "OLE2文档(旧版Office)",
        b'SQLite format': "SQLite数据库",
        b'\x1f\x8b': "GZIP压缩",
        b'BZ': "BZ2压缩",
        b'\x42\x5a\x68': "BZ2压缩",
        b'\xfd7zXZ': "XZ压缩",
        b'RIFF': "RIFF容器",
        b'ID3': "MP3音频",
        b'\x00\x00\x00\x1c\x66\x74\x79\x70': "MP4视频",
        b'\x00\x00\x00\x18\x66\x74\x79\x70': "MP4视频",
        b'\x49\x49\x2a\x00': "TIFF图片(LE)",
        b'\x4d\x4d\x00\x2a': "TIFF图片(BE)",
        b'\x00\x00\x01\x00': "ICO图标",
        b'BM': "BMP图片",
        b'<?xml': "XML文档",
        b'{': "JSON文档",
    }
    for sig, name in signatures.items():
        if header.startswith(sig):
            return name
    return "未知类型"


def recover_deleted_files(filepath: str) -> dict:
    """尝试从磁盘镜像中恢复删除的文件（基于文件头搜索）"""
    with open(filepath, 'rb') as f:
        data = f.read()

    # 常见文件头签名
    file_signatures = [
        (b'\xff\xd8\xff\xe0', "JPEG", ".jpg"),
        (b'\xff\xd8\xff\xe1', "JPEG", ".jpg"),
        (b'\x89PNG\r\n\x1a\n', "PNG", ".png"),
        (b'GIF87a', "GIF", ".gif"),
        (b'GIF89a', "GIF", ".gif"),
        (b'PK\x03\x04', "ZIP", ".zip"),
        (b'%PDF', "PDF", ".pdf"),
        (b'Rar!\x1a\x07', "RAR", ".rar"),
        (b'\x7fELF', "ELF", ".elf"),
        (b'MZ', "PE", ".exe"),
    ]

    found = []
    for sig, name, ext in file_signatures:
        pos = 0
        while True:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            found.append({
                "offset": idx,
                "offset_hex": hex(idx),
                "type": name,
                "ext": ext,
            })
            pos = idx + len(sig)

    # 尝试提取找到的文件
    extracted = []
    output_dir = filepath + "_recovered"
    os.makedirs(output_dir, exist_ok=True)

    for i, item in enumerate(found[:50]):
        offset = item["offset"]
        # 简单提取：取到下一个文件头或固定大小
        end = min(offset + 10 * 1024 * 1024, len(data))  # 最大10MB
        for sig, _, _ in file_signatures:
            next_pos = data.find(sig, offset + len(sig))
            if next_pos != -1 and next_pos < end:
                end = next_pos

        file_data = data[offset:end]
        if len(file_data) > 100:
            out_path = os.path.join(output_dir, f"recovered_{i}{item['ext']}")
            try:
                with open(out_path, 'wb') as f:
                    f.write(file_data)
                extracted.append({"path": out_path, "size": len(file_data), "type": item["type"]})
            except Exception:
                pass

    flags = find_flags_in_text(data.decode('utf-8', errors='ignore'))

    return {
        "success": True,
        "found_signatures": len(found),
        "signatures": found[:20],
        "extracted_count": len(extracted),
        "extracted": extracted[:20],
        "output_dir": output_dir,
        "flags": flags
    }


def analyze_memory_dump(filepath: str) -> dict:
    """分析内存转储文件（基础字符串提取）"""
    with open(filepath, 'rb') as f:
        # 只读取前100MB避免内存溢出
        data = f.read(100 * 1024 * 1024)

    strings = extract_strings(data, min_len=6)
    flags = find_flags_in_strings(strings)

    # 搜索可能的密码
    password_patterns = [
        r'(?i)password\s*[=:]\s*(\S+)',
        r'(?i)passwd\s*[=:]\s*(\S+)',
        r'(?i)secret\s*[=:]\s*(\S+)',
        r'(?i)token\s*[=:]\s*(\S+)',
        r'(?i)key\s*[=:]\s*(\S+)',
    ]
    passwords = []
    text = ' '.join(strings[:10000])
    for pat in password_patterns:
        matches = re.findall(pat, text)
        passwords.extend(matches)

    # 搜索进程名
    process_names = []
    process_patterns = [r'([a-zA-Z_]+\.exe)', r'(/usr/bin/\S+)', r'(/bin/\S+)']
    for pat in process_patterns:
        matches = re.findall(pat, text)
        process_names.extend(matches)

    # 搜索网络连接
    ip_port = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', text)

    # 搜索URL
    urls = re.findall(r'https?://[^\s"\'<>]+', text)

    return {
        "success": True,
        "file_size": os.path.getsize(filepath),
        "string_count": len(strings),
        "flags": flags,
        "possible_passwords": list(set(passwords))[:20],
        "process_names": list(set(process_names))[:30],
        "network_connections": list(set(ip_port))[:20],
        "urls": list(set(urls))[:20],
        "sample_strings": strings[:50]
    }


def extract_strings_from_dump(filepath: str, min_len: int = 6) -> dict:
    """从任意文件中提取可打印字符串（类strings命令）"""
    with open(filepath, 'rb') as f:
        data = f.read()

    strings = extract_strings(data, min_len=min_len)
    flags = find_flags_in_strings(strings)

    # 分类统计
    urls = re.findall(r'https?://[^\s"\'<>]+', ' '.join(strings[:10000]))
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ' '.join(strings[:10000]))
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', ' '.join(strings[:10000]))
    paths_win = re.findall(r'[A-Z]:\\[^\s"\'<>]+', ' '.join(strings[:10000]))
    paths_linux = re.findall(r'(?:/[\w.-]+){2,}', ' '.join(strings[:10000]))

    return {
        "success": True,
        "total_strings": len(strings),
        "flags": flags,
        "urls": list(set(urls))[:20],
        "ips": list(set(ips))[:20],
        "emails": list(set(emails))[:20],
        "windows_paths": list(set(paths_win))[:20],
        "linux_paths": list(set(paths_linux))[:20],
        "strings": strings[:500]
    }


def analyze_pcap_for_forensics(filepath: str) -> dict:
    """从pcap中提取取证相关信息"""
    try:
        from scapy.all import rdpcap, TCP, UDP, Raw, DNS, IP

        packets = rdpcap(filepath)

        evidence = {
            "files_transferred": [],
            "credentials": [],
            "dns_queries": [],
            "http_requests": [],
            "emails": [],
            "flags": [],
        }

        for pkt in packets:
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                text = payload.decode('utf-8', errors='ignore')

                # 检测文件传输
                if payload[:4] == b'PK\x03\x04':
                    evidence["files_transferred"].append({"type": "ZIP", "size": len(payload)})
                elif payload[:3] == b'\xff\xd8\xff':
                    evidence["files_transferred"].append({"type": "JPEG", "size": len(payload)})
                elif payload[:8] == b'\x89PNG\r\n\x1a\n':
                    evidence["files_transferred"].append({"type": "PNG", "size": len(payload)})

                # 检测凭据
                if 'Authorization:' in text:
                    m = re.search(r'Authorization:\s*(\S+)', text)
                    if m:
                        evidence["credentials"].append({"type": "HTTP Auth", "value": m.group(1)[:100]})
                if 'Cookie:' in text:
                    m = re.search(r'Cookie:\s*(.+)', text)
                    if m:
                        evidence["credentials"].append({"type": "Cookie", "value": m.group(1)[:100]})
                if 'USER ' in text and 'PASS ' in text:
                    evidence["credentials"].append({"type": "FTP", "value": text[:200]})

                # Flag搜索
                evidence["flags"].extend(find_flags_in_text(text))

            # DNS查询
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                for i in range(pkt[DNS].qdcount):
                    try:
                        qname = pkt[DNS].qd[i].qname.decode('utf-8', errors='ignore')
                        evidence["dns_queries"].append(qname)
                    except Exception:
                        pass

        evidence["flags"] = list(set(evidence["flags"]))
        evidence["success"] = True
        evidence["total_packets"] = len(packets)

        return evidence
    except ImportError:
        return {"success": False, "error": "scapy未安装，请运行: pip install scapy"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def volatility_commands(dump_type: str = "memory") -> dict:
    """生成Volatility内存取证命令"""
    cmds = {
        "基础信息": [
            {"cmd": "volatility -f dump.raw imageinfo", "desc": "识别镜像类型(Volatility 2)"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 pslist", "desc": "进程列表"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 pstree", "desc": "进程树"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 cmdline", "desc": "进程命令行"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 netscan", "desc": "网络连接"},
        ],
        "文件提取": [
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 filescan", "desc": "扫描文件"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 dumpfiles -Q <offset> -D output/", "desc": "提取文件"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 dumpfiles -Q 0x00000000 -D output/", "desc": "按偏移提取"},
        ],
        "密码提取": [
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 hashdump", "desc": "提取NTLM哈希"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 lsadump", "desc": "提取LSA密钥"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 cachedump", "desc": "提取缓存凭据"},
        ],
        "注册表": [
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 hivelist", "desc": "注册表hive列表"},
            {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 printkey -K 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'", "desc": "自启动项"},
        ],
        "Volatility3": [
            {"cmd": "vol -f dump.raw windows.info", "desc": "系统信息"},
            {"cmd": "vol -f dump.raw windows.pslist", "desc": "进程列表"},
            {"cmd": "vol -f dump.raw windows.pstree", "desc": "进程树"},
            {"cmd": "vol -f dump.raw windows.netscan", "desc": "网络连接"},
            {"cmd": "vol -f dump.raw windows.filescan", "desc": "文件扫描"},
            {"cmd": "vol -f dump.raw windows.hashdump", "desc": "密码哈希"},
            {"cmd": "vol -f dump.raw windows.cmdline", "desc": "命令行"},
            {"cmd": "vol -f dump.raw windows.dlllist", "desc": "DLL列表"},
            {"cmd": "vol -f dump.raw windows.malfind", "desc": "检测注入代码"},
            {"cmd": "vol -f dump.raw windows.registry.hivelist", "desc": "注册表"},
        ]
    }

    if dump_type == "all":
        return {"success": True, "commands": cmds}
    if dump_type in cmds:
        return {"success": True, "category": dump_type, "commands": cmds[dump_type]}
    return {"success": True, "commands": cmds}


def disk_forensics_commands() -> dict:
    """磁盘取证常用命令"""
    return {
        "success": True,
        "Autopsy/SleuthKit": [
            {"cmd": "fls -r -m / image.dd", "desc": "递归列出文件(带删除标记)"},
            {"cmd": "icat image.dd <inode>", "desc": "按inode提取文件"},
            {"cmd": "istat image.dd <inode>", "desc": "查看inode详细信息(时间戳)"},
            {"cmd": "mmls image.dd", "desc": "显示分区表"},
            {"cmd": "ffind image.dd <inode>", "desc": "按inode找文件名"},
            {"cmd": "tsk_recover image.dd output/", "desc": "恢复删除的文件"},
            {"cmd": "mactime -b body.txt", "desc": "生成时间线"},
        ],
        "文件恢复": [
            {"cmd": "foremost -i image.dd -o output/", "desc": "按文件头恢复"},
            {"cmd": "scalpel image.dd -o output/", "desc": "按文件签名恢复"},
            {"cmd": "photorec image.dd", "desc": "交互式文件恢复"},
            {"cmd": "testdisk image.dd", "desc": "分区恢复"},
        ],
        "磁盘镜像": [
            {"cmd": "dd if=/dev/sda of=image.dd bs=4M", "desc": "创建磁盘镜像"},
            {"cmd": "dcfldd if=/dev/sda of=image.dd hash=sha256 hashlog=hash.txt", "desc": "带哈希校验的镜像"},
            {"cmd": "ewfmount image.E01 /mnt/ewf/", "desc": "挂载E01镜像"},
            {"cmd": "mount -o loop,ro image.dd /mnt/img/", "desc": "挂载DD镜像(只读)"},
        ],
        "时间线分析": [
            {"cmd": "fls -m / -r image.dd > body.txt", "desc": "生成body文件"},
            {"cmd": "mactime -b body.txt -d > timeline.csv", "desc": "生成CSV时间线"},
            {"cmd": "log2timeline.py timeline.plaso image.dd", "desc": "Plaso时间线"},
            {"cmd": "psort.py -o l2tcsv timeline.plaso > timeline.csv", "desc": "Plaso排序输出"},
        ]
    }


def evidence_collection_guide() -> dict:
    """电子证据收集指南"""
    return {
        "success": True,
        "证据收集原则": [
            "1. 最小化原则: 只收集与案件相关的数据",
            "2. 完整性原则: 确保数据未被篡改(计算哈希)",
            "3. 可追溯原则: 记录每一步操作",
            "4. 及时性原则: 尽快收集，避免数据丢失",
        ],
        "哈希校验": [
            {"cmd": "md5sum evidence.dd", "desc": "MD5校验"},
            {"cmd": "sha256sum evidence.dd", "desc": "SHA256校验"},
            {"cmd": "md5sum evidence.dd > evidence.md5", "desc": "保存校验值"},
        ],
        "写保护": [
            "硬件写保护设备(推荐)",
            "软件写保护: mount -o ro",
            "dd创建镜像: dd if=/dev/sda of=image.dd bs=4M",
        ],
        "证据链文档": [
            "收集时间、地点、人员",
            "设备型号、序列号",
            "哈希值(收集前后各算一次)",
            "存储介质信息",
            "操作步骤记录",
        ]
    }


# ============ 扩展取证功能 ============

def hex_dump(filepath: str, offset: int = 0, length: int = 512) -> dict:
    """十六进制转储分析（类xxd命令）"""
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            f.seek(offset)
            data = f.read(length)

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append({
                "offset": f"0x{offset+i:08x}",
                "hex": hex_part,
                "ascii": ascii_part
            })

        # 搜索flag
        flags = find_flags_in_text(data.decode('utf-8', errors='ignore'))

        return {
            "success": True,
            "file_size": file_size,
            "dump_offset": offset,
            "dump_length": len(data),
            "lines": lines,
            "flags": flags
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def file_signature_scan(filepath: str) -> dict:
    """深度文件签名扫描 - 检测文件类型、嵌入文件、隐藏数据"""
    with open(filepath, 'rb') as f:
        data = f.read()

    file_size = len(data)
    findings = []

    # 扩展签名库
    signatures = [
        (b'\xff\xd8\xff', "JPEG图片", "image/jpeg"),
        (b'\x89PNG\r\n\x1a\n', "PNG图片", "image/png"),
        (b'GIF87a', "GIF87a图片", "image/gif"),
        (b'GIF89a', "GIF89a图片", "image/gif"),
        (b'PK\x03\x04', "ZIP压缩包", "application/zip"),
        (b'PK\x05\x06', "ZIP空压缩包", "application/zip"),
        (b'Rar!\x1a\x07', "RAR压缩包", "application/x-rar"),
        (b'\x7fELF', "ELF可执行文件", "application/x-elf"),
        (b'MZ', "PE可执行文件", "application/x-pe"),
        (b'%PDF', "PDF文档", "application/pdf"),
        (b'\xd0\xcf\x11\xe0', "OLE2文档", "application/x-ole2"),
        (b'SQLite format', "SQLite数据库", "application/x-sqlite"),
        (b'\x1f\x8b', "GZIP压缩", "application/gzip"),
        (b'\x42\x5a\x68', "BZ2压缩", "application/x-bzip2"),
        (b'\xfd7zXZ', "XZ压缩", "application/x-xz"),
        (b'RIFF', "RIFF容器", "application/x-riff"),
        (b'ID3', "MP3音频", "audio/mpeg"),
        (b'\xff\xfb', "MP3音频", "audio/mpeg"),
        (b'\x49\x49\x2a\x00', "TIFF图片(LE)", "image/tiff"),
        (b'\x4d\x4d\x00\x2a', "TIFF图片(BE)", "image/tiff"),
        (b'\x00\x00\x01\x00', "ICO图标", "image/x-icon"),
        (b'BM', "BMP图片", "image/bmp"),
        (b'\x00\x00\x00\x1c\x66\x74\x79\x70', "MP4视频", "video/mp4"),
        (b'\x00\x00\x00\x18\x66\x74\x79\x70', "MP4视频", "video/mp4"),
        (b'\x00\x00\x00\x20\x66\x74\x79\x70', "MP4/M4A", "video/mp4"),
        (b'fLaC', "FLAC音频", "audio/flac"),
        (b'OggS', "OGG容器", "audio/ogg"),
        (b'\x1a\x45\xdf\xa3', "MKV/WebM视频", "video/x-matroska"),
        (b'<!DOCTYPE', "HTML文档", "text/html"),
        (b'<?xml', "XML文档", "text/xml"),
        (b'\xef\xbb\xbf', "UTF-8 BOM", "text/plain"),
        (b'\xff\xfe', "UTF-16 LE BOM", "text/plain"),
        (b'\xfe\xff', "UTF-16 BE BOM", "text/plain"),
    ]

    # 扫描文件头
    header_type = "未知"
    for sig, name, mime in signatures:
        if data.startswith(sig):
            header_type = name
            findings.append({"type": "文件头", "desc": f"主文件类型: {name}", "offset": 0})
            break

    # 扫描嵌入的文件签名
    embedded = []
    for sig, name, mime in signatures[1:]:  # 跳过第一个匹配
        pos = 0
        while True:
            idx = data.find(sig, pos)
            if idx == -1 or idx > file_size - 100:
                break
            if idx > 0:  # 不是文件头
                embedded.append({
                    "offset": idx,
                    "offset_hex": hex(idx),
                    "type": name,
                    "mime": mime
                })
            pos = idx + len(sig)

    if embedded:
        findings.append({"type": "嵌入文件", "desc": f"发现{len(embedded)}个嵌入文件签名", "details": embedded[:20]})

    # 搜索隐藏数据特征
    # 检查文件尾部是否有附加数据
    if data[-2:] == b'\xff\xd9':  # JPEG正常结束
        findings.append({"type": "文件完整性", "desc": "JPEG文件正常结束(FF D9)"})
    elif header_type == "JPEG图片" and b'\xff\xd9' in data[100:]:
        end_pos = data.rfind(b'\xff\xd9')
        if end_pos < file_size - 10:
            findings.append({"type": "可疑", "desc": f"JPEG结束标记后有{file_size - end_pos - 2}字节附加数据"})

    # 检查ZIP尾部
    if header_type == "ZIP压缩包":
        eocd_pos = data.rfind(b'PK\x05\x06')
        if eocd_pos != -1:
            comment_len = struct.unpack('<H', data[eocd_pos+20:eocd_pos+22])[0] if eocd_pos + 22 <= len(data) else 0
            if comment_len > 0:
                findings.append({"type": "可疑", "desc": f"ZIP文件包含{comment_len}字节注释"})

    # 检查零填充区域
    null_runs = []
    pos = 0
    while pos < len(data):
        if data[pos:pos+100] == b'\x00' * 100:
            start = pos
            while pos < len(data) and data[pos] == 0:
                pos += 1
            run_len = pos - start
            if run_len > 1024:
                null_runs.append({"offset": start, "size": run_len})
        else:
            pos += 1
    if null_runs:
        findings.append({"type": "零填充", "desc": f"发现{len(null_runs)}个大块零填充区域", "details": null_runs[:5]})

    # 提取字符串中的flag
    flags = find_flags_in_text(data.decode('utf-8', errors='ignore'))

    return {
        "success": True,
        "filename": os.path.basename(filepath),
        "file_size": file_size,
        "header_type": header_type,
        "findings": findings,
        "embedded_files": embedded[:30],
        "flags": flags
    }


def exif_analysis(filepath: str) -> dict:
    """EXIF元数据分析（图片文件）"""
    with open(filepath, 'rb') as f:
        data = f.read(65536)  # 读取前64KB

    result = {
        "success": True,
        "filename": os.path.basename(filepath),
        "file_size": os.path.getsize(filepath),
    }

    # 检查是否JPEG
    if not data.startswith(b'\xff\xd8'):
        return {"success": False, "error": "不是JPEG文件，无法提取EXIF"}

    # 简单解析EXIF APP1段
    pos = 2
    exif_data = {}
    while pos < len(data) - 4:
        if data[pos] != 0xff:
            break
        marker = data[pos+1]
        if marker == 0xe1:  # APP1 = EXIF
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            segment = data[pos+4:pos+2+length]
            if segment.startswith(b'Exif\x00\x00'):
                exif_raw = segment[6:]
                # 提取可打印字符串
                exif_strings = extract_strings(exif_raw, min_len=3)
                exif_data["raw_strings"] = exif_strings[:50]
                exif_data["segment_size"] = length
                # 搜索时间戳
                for s in exif_strings:
                    if re.match(r'\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}', s):
                        exif_data.setdefault("timestamps", []).append(s)
                    if 'GPS' in s or 'gps' in s:
                        exif_data.setdefault("gps_strings", []).append(s)
                    if any(kw in s.lower() for kw in ['camera', 'make', 'model', 'software', 'author']):
                        exif_data.setdefault("device_info", []).append(s)
            break
        elif marker == 0xda:  # SOS - 图像数据开始
            break
        else:
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            pos += 2 + length
            continue
        pos += 2 + length

    result["exif"] = exif_data

    # 搜索flag
    flags = find_flags_in_text(data.decode('utf-8', errors='ignore'))
    result["flags"] = flags

    # 检查是否有隐藏数据（JPEG注释段）
    comments = []
    pos = 2
    while pos < len(data) - 4:
        if data[pos] != 0xff:
            break
        marker = data[pos+1]
        if marker == 0xfe:  # COM注释段
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            comment = data[pos+4:pos+2+length]
            try:
                comments.append(comment.decode('utf-8', errors='replace'))
            except Exception:
                comments.append(comment.hex())
            pos += 2 + length
        elif marker == 0xda:
            break
        else:
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            pos += 2 + length

    if comments:
        result["comments"] = comments

    return result


def sqlite_analysis(filepath: str) -> dict:
    """SQLite数据库取证分析"""
    try:
        import sqlite3
    except ImportError:
        return {"success": False, "error": "sqlite3模块不可用"}

    try:
        conn = sqlite3.connect(filepath)
        cursor = conn.cursor()

        # 获取所有表
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        result = {
            "success": True,
            "filename": os.path.basename(filepath),
            "file_size": os.path.getsize(filepath),
            "tables": [],
            "deleted_data_hints": []
        }

        for table_name, create_sql in tables:
            table_info = {"name": table_name, "create_sql": create_sql, "columns": [], "row_count": 0, "sample": []}

            # 获取列信息
            cursor.execute(f"PRAGMA table_info('{table_name}')")
            columns = cursor.fetchall()
            table_info["columns"] = [{"name": col[1], "type": col[2], "notnull": col[3], "default": col[4]} for col in columns]

            # 获取行数
            try:
                cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                table_info["row_count"] = cursor.fetchone()[0]
            except Exception:
                pass

            # 获取样本数据
            try:
                cursor.execute(f"SELECT * FROM '{table_name}' LIMIT 5")
                rows = cursor.fetchall()
                col_names = [col[1] for col in columns]
                for row in rows:
                    table_info["sample"].append(dict(zip(col_names, row)))
            except Exception:
                pass

            result["tables"].append(table_info)

        # 搜索可能的敏感数据（所有表的文本列）
        all_strings = []
        for table_name, _ in tables:
            try:
                cursor.execute(f"SELECT * FROM '{table_name}'")
                for row in cursor.fetchall():
                    for val in row:
                        if isinstance(val, str) and len(val) > 2:
                            all_strings.append(val)
            except Exception:
                pass

        # 搜索flag
        flags = find_flags_in_strings(all_strings)
        result["flags"] = flags

        # 搜索敏感信息
        all_text = ' '.join(all_strings[:5000])
        result["sensitive"] = {
            "emails": list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_text)))[:10],
            "phones": list(set(re.findall(r'1[3-9]\d{9}', all_text)))[:10],
            "ips": list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', all_text)))[:10],
        }

        conn.close()
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def timeline_analysis(filepath: str) -> dict:
    """文件时间线分析（基于文件系统元数据）"""
    try:
        stat = os.stat(filepath)
        timestamps = {
            "创建时间": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "修改时间": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "访问时间": datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
        }

        # 读取文件，搜索内嵌时间戳
        with open(filepath, 'rb') as f:
            data = f.read(1024 * 1024)  # 读1MB

        text = data.decode('utf-8', errors='ignore')

        # 搜索常见时间格式
        time_patterns = [
            (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', "ISO格式"),
            (r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}', "美式格式"),
            (r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}', "中式格式"),
            (r'\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}', "Unix日志格式"),
            (r'\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}', "EXIF格式"),
        ]

        embedded_times = []
        for pattern, fmt_name in time_patterns:
            matches = re.findall(pattern, text)
            for m in matches[:20]:
                embedded_times.append({"value": m, "format": fmt_name})

        # 提取字符串中的时间相关
        flags = find_flags_in_text(text)

        return {
            "success": True,
            "filename": os.path.basename(filepath),
            "file_size": stat.st_size,
            "filesystem_timestamps": timestamps,
            "embedded_timestamps": embedded_times[:50],
            "flags": flags
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def registry_analysis(filepath: str) -> dict:
    """Windows注册表文件分析（REGF格式）"""
    with open(filepath, 'rb') as f:
        data = f.read()

    result = {
        "success": True,
        "filename": os.path.basename(filepath),
        "file_size": len(data),
    }

    # 检查REGF签名
    if data[:4] != b'regf':
        return {"success": False, "error": "不是有效的注册表文件（缺少regf签名）"}

    # 提取注册表中的可打印字符串
    strings = extract_strings(data, min_len=4)

    # 分类搜索
    reg_keys = []
    reg_values = []
    for s in strings:
        if '\\' in s and any(kw in s.upper() for kw in ['SOFTWARE', 'SYSTEM', 'SAM', 'SECURITY', 'DEFAULT', 'NTUSER']):
            reg_keys.append(s)
        if '=' in s and len(s) < 200:
            reg_values.append(s)

    # 搜索自启动项
    autostart = [s for s in strings if any(kw in s.lower() for kw in ['run', 'startup', 'autorun', 'shell'])]

    # 搜索网络相关
    network = [s for s in strings if any(kw in s.lower() for kw in ['tcp', 'udp', 'http', 'dns', 'proxy', 'network'])]

    # 搜索用户相关
    users = [s for s in strings if any(kw in s.lower() for kw in ['user', 'password', 'sid', 'profile', 'login'])]

    # Flag搜索
    flags = find_flags_in_strings(strings)

    result.update({
        "total_strings": len(strings),
        "registry_keys": list(set(reg_keys))[:30],
        "registry_values": list(set(reg_values))[:30],
        "autostart_entries": list(set(autostart))[:20],
        "network_entries": list(set(network))[:20],
        "user_entries": list(set(users))[:20],
        "flags": flags,
        "sample_strings": strings[:100]
    })

    return result


def stego_detect(filepath: str) -> dict:
    """隐写术检测提示（基于文件结构异常）"""
    with open(filepath, 'rb') as f:
        data = f.read()

    result = {
        "success": True,
        "filename": os.path.basename(filepath),
        "file_size": len(data),
        "suspicious": [],
        "suggestions": []
    }

    header = data[:16]

    # JPEG检测
    if header.startswith(b'\xff\xd8\xff'):
        result["file_type"] = "JPEG"
        # 检查是否有额外数据
        eoi = data.rfind(b'\xff\xd9')
        if eoi != -1 and eoi < len(data) - 2:
            extra = len(data) - eoi - 2
            result["suspicious"].append(f"JPEG结束标记后有{extra}字节附加数据（可能隐藏信息）")
            result["suggestions"].append("使用 binwalk 提取附加数据")
        # 检查注释段
        com_pos = data.find(b'\xff\xfe')
        if com_pos != -1:
            com_len = struct.unpack('>H', data[com_pos+2:com_pos+4])[0]
            result["suspicious"].append(f"JPEG包含注释段(COM)，长度{com_len}字节")
        # 检查APP段是否有异常大小
        pos = 2
        while pos < min(len(data), 10000):
            if data[pos] != 0xff:
                break
            marker = data[pos+1]
            if marker == 0xda:
                break
            if marker in (0xe0, 0xe1, 0xe2, 0xfe):
                seg_len = struct.unpack('>H', data[pos+2:pos+4])[0]
                if seg_len > 5000 and marker not in (0xe0, 0xe1):
                    result["suspicious"].append(f"异常大的APP段(marker=0x{marker:02x})，长度{seg_len}")
            try:
                seg_len = struct.unpack('>H', data[pos+2:pos+4])[0]
                pos += 2 + seg_len
            except Exception:
                break

    # PNG检测
    elif header.startswith(b'\x89PNG'):
        result["file_type"] = "PNG"
        # 检查IDAT块
        idat_count = data.count(b'IDAT')
        result["suspicious"].append(f"PNG包含{idat_count}个IDAT数据块")
        # 检查是否有非标准chunk
        pos = 8
        chunks = []
        while pos < len(data) - 8:
            try:
                chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
                chunks.append(chunk_type)
                if chunk_type == 'IEND':
                    break
                pos += 12 + chunk_len
            except Exception:
                break
        standard_chunks = {'IHDR', 'PLTE', 'IDAT', 'IEND', 'tEXt', 'zTXt', 'iTXt', 'gAMA', 'cHRM', 'sRGB', 'tIME', 'pHYs', 'bKGD'}
        for c in chunks:
            if c not in standard_chunks:
                result["suspicious"].append(f"非标准PNG chunk: {c}")

    # BMP检测
    elif header.startswith(b'BM'):
        result["file_type"] = "BMP"
        # BMP像素数据偏移
        pixel_offset = struct.unpack('<I', data[10:14])[0]
        if pixel_offset > 100:
            result["suspicious"].append(f"BMP像素数据偏移较大({pixel_offset}字节)，头区域可能隐藏数据")

    result["suggestions"].extend([
        "使用 steghide 提取隐写数据（JPEG/BMP）",
        "使用 zsteg 分析PNG隐写",
        "使用 stegsolve 查看各通道",
        "使用 binwalk 检测嵌入文件",
    ])

    # Flag搜索
    flags = find_flags_in_text(data.decode('utf-8', errors='ignore'))
    result["flags"] = flags

    return result


def network_forensics_commands() -> dict:
    """网络取证命令集"""
    return {
        "success": True,
        "流量捕获": [
            {"cmd": "tcpdump -i eth0 -w capture.pcap", "desc": "抓包保存"},
            {"cmd": "tcpdump -i eth0 -w capture.pcap -c 1000", "desc": "抓1000个包"},
            {"cmd": "tcpdump -r capture.pcap", "desc": "读取pcap"},
            {"cmd": "tcpdump -r capture.pcap 'port 80'", "desc": "过滤HTTP流量"},
            {"cmd": "tcpdump -r capture.pcap 'host 192.168.1.1'", "desc": "过滤特定主机"},
        ],
        "Wireshark过滤": [
            {"cmd": "http.request.method == \"POST\"", "desc": "HTTP POST请求"},
            {"cmd": "tcp.flags.syn == 1", "desc": "SYN包(TCP握手)"},
            {"cmd": "dns", "desc": "DNS查询"},
            {"cmd": "ip.addr == 192.168.1.1", "desc": "特定IP流量"},
            {"cmd": "tcp.stream eq 0", "desc": "TCP流0"},
            {"cmd": "frame contains \"flag\"", "desc": "包含flag的帧"},
            {"cmd": "http contains \"password\"", "desc": "HTTP中的密码"},
        ],
        "NetFlow分析": [
            {"cmd": "nfdump -r nfcapd.20240101", "desc": "读取NetFlow数据"},
            {"cmd": "nfdump -r nfcapd -s srcip/20", "desc": "按源IP统计"},
            {"cmd": "nfdump -r nfcapd 'dst port 80'", "desc": "过滤目标端口"},
        ],
        "协议分析": [
            {"cmd": "strings capture.pcap | grep -i flag", "desc": "从pcap提取字符串"},
            {"cmd": "tshark -r capture.pcap -T fields -e http.host", "desc": "提取HTTP主机"},
            {"cmd": "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name", "desc": "提取DNS查询"},
            {"cmd": "tshark -r capture.pcap -Y 'ftp' -T fields -e ftp.request.command", "desc": "FTP命令"},
        ]
    }


def mobile_forensics_commands() -> dict:
    """移动设备取证命令"""
    return {
        "success": True,
        "Android": [
            {"cmd": "adb devices", "desc": "列出连接设备"},
            {"cmd": "adb shell dumpsys battery", "desc": "电池信息"},
            {"cmd": "adb shell getprop", "desc": "系统属性"},
            {"cmd": "adb shell pm list packages", "desc": "安装的应用列表"},
            {"cmd": "adb pull /sdcard/ ./evidence/", "desc": "拉取SD卡数据"},
            {"cmd": "adb backup -all -f backup.ab", "desc": "全量备份"},
            {"cmd": "adb shell sqlite3 /data/data/*/databases/*.db", "desc": "查看应用数据库"},
        ],
        "iOS": [
            {"cmd": "ideviceinfo", "desc": "设备信息"},
            {"cmd": "idevicebackup2 backup ./backup/", "desc": "iTunes备份"},
            {"cmd": "ideviceinstaller -l", "desc": "已安装应用"},
        ],
        "备份解析": [
            {"cmd": "abp -unpack backup.ab", "desc": "Android备份解包"},
            {"cmd": "libimobiledevice --backup", "desc": "iOS备份工具"},
        ]
    }


def competition_forensics_task(task_num: int, config: dict = None) -> dict:
    """竞赛电子取证题目一键生成"""
    if config is None:
        config = {}

    tasks = {
        1: {
            "title": "文件元数据与哈希校验",
            "description": "计算文件的MD5/SHA256哈希值，提取文件元数据信息",
            "steps": [
                "1. 计算文件哈希值: md5sum / sha256sum <文件>",
                "2. 查看文件类型: file <文件>",
                "3. 提取文件字符串: strings <文件> | head -100",
                "4. 分析文件头: xxd <文件> | head -20",
                "5. 使用工具箱上传文件，点击「文件元数据」自动分析"
            ],
            "tool_commands": [
                {"cmd": "md5sum evidence.bin", "desc": "计算MD5"},
                {"cmd": "sha256sum evidence.bin", "desc": "计算SHA256"},
                {"cmd": "file evidence.bin", "desc": "检测文件类型"},
                {"cmd": "xxd evidence.bin | head -20", "desc": "查看文件头"},
                {"cmd": "strings evidence.bin | grep -i flag", "desc": "搜索flag"},
            ]
        },
        2: {
            "title": "文件恢复与磁盘取证",
            "description": "从磁盘镜像中恢复已删除的文件",
            "steps": [
                "1. 查看分区表: mmls image.dd",
                "2. 列出所有文件(含删除): fls -r -m / image.dd",
                "3. 按inode提取文件: icat image.dd <inode>",
                "4. 恢复删除文件: tsk_recover image.dd output/",
                "5. 使用工具箱上传镜像，点击「文件恢复」自动扫描"
            ],
            "tool_commands": [
                {"cmd": "mmls image.dd", "desc": "查看分区表"},
                {"cmd": "fls -r -m / image.dd", "desc": "列出所有文件"},
                {"cmd": "icat image.dd <inode>", "desc": "提取文件"},
                {"cmd": "tsk_recover image.dd output/", "desc": "批量恢复"},
                {"cmd": "foremost -i image.dd -o output/", "desc": "按文件头恢复"},
            ]
        },
        3: {
            "title": "内存取证分析",
            "description": "分析内存转储文件，提取进程、网络连接、密码等信息",
            "steps": [
                "1. 识别镜像: volatility -f dump.raw imageinfo",
                "2. 查看进程: volatility -f dump.raw --profile=<profile> pslist",
                "3. 查看网络连接: volatility -f dump.raw --profile=<profile> netscan",
                "4. 提取密码哈希: volatility -f dump.raw --profile=<profile> hashdump",
                "5. 搜索flag: volatility -f dump.raw --profile=<profile> yarascan -Y 'flag{'"
            ],
            "tool_commands": [
                {"cmd": "volatility -f dump.raw imageinfo", "desc": "识别镜像"},
                {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 pslist", "desc": "进程列表"},
                {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 pstree", "desc": "进程树"},
                {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 netscan", "desc": "网络连接"},
                {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 hashdump", "desc": "密码哈希"},
                {"cmd": "volatility -f dump.raw --profile=Win7SP1x64 cmdline", "desc": "命令行"},
                {"cmd": "vol -f dump.raw windows.info", "desc": "Volatility3系统信息"},
                {"cmd": "vol -f dump.raw windows.pslist", "desc": "Volatility3进程"},
                {"cmd": "vol -f dump.raw windows.netscan", "desc": "Volatility3网络"},
            ]
        },
        4: {
            "title": "流量取证分析",
            "description": "从pcap文件中提取证据：文件、凭据、DNS查询等",
            "steps": [
                "1. 统计协议分布: tshark -r capture.pcap -z io,phs",
                "2. 提取HTTP请求: tshark -r capture.pcap -Y 'http.request'",
                "3. 提取DNS查询: tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name",
                "4. 提取文件: foremost -i capture.pcap -o output/",
                "5. 搜索flag: strings capture.pcap | grep -i flag"
            ],
            "tool_commands": [
                {"cmd": "tshark -r capture.pcap -z io,phs", "desc": "协议统计"},
                {"cmd": "tshark -r capture.pcap -Y 'http.request'", "desc": "HTTP请求"},
                {"cmd": "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name", "desc": "DNS查询"},
                {"cmd": "foremost -i capture.pcap -o output/", "desc": "提取文件"},
                {"cmd": "strings capture.pcap | grep -i flag", "desc": "搜索flag"},
            ]
        },
        5: {
            "title": "文件签名与隐写检测",
            "description": "检测文件真实类型、嵌入文件、隐写数据",
            "steps": [
                "1. 检查文件头: xxd <文件> | head -5",
                "2. 真实类型检测: file <文件>",
                "3. binwalk扫描: binwalk -e <文件>",
                "4. strings搜索: strings <文件> | grep -i flag",
                "5. 使用工具箱上传文件，点击「签名检测」和「隐写检测」"
            ],
            "tool_commands": [
                {"cmd": "xxd suspicious.bin | head -5", "desc": "查看文件头"},
                {"cmd": "file suspicious.bin", "desc": "文件类型"},
                {"cmd": "binwalk -e suspicious.bin", "desc": "提取嵌入文件"},
                {"cmd": "binwalk -A suspicious.bin", "desc": "熵分析"},
                {"cmd": "strings suspicious.bin | grep -i flag", "desc": "搜索flag"},
            ]
        },
        6: {
            "title": "注册表取证",
            "description": "分析Windows注册表文件，提取自启动项、用户信息等",
            "steps": [
                "1. 列出注册表hive: volatility -f dump.raw hivelist",
                "2. 查看自启动项: volatility -f dump.raw printkey -K 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                "3. 提取用户信息: volatility -f dump.raw hashdump",
                "4. 查看最近文档: volatility -f dump.raw printkey -K 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs'",
            ],
            "tool_commands": [
                {"cmd": "volatility -f dump.raw hivelist", "desc": "注册表hive列表"},
                {"cmd": "volatility -f dump.raw printkey -K 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'", "desc": "自启动项"},
                {"cmd": "volatility -f dump.raw hashdump", "desc": "密码哈希"},
                {"cmd": "volatility -f dump.raw userassist", "desc": "用户操作记录"},
                {"cmd": "volatility -f dump.raw shellbags", "desc": "ShellBags记录"},
            ]
        },
        7: {
            "title": "SQLite数据库取证",
            "description": "分析SQLite数据库，提取已删除数据和敏感信息",
            "steps": [
                "1. 打开数据库: sqlite3 database.db",
                "2. 查看表结构: .schema",
                "3. 查看数据: SELECT * FROM <table>",
                "4. 搜索已删除记录: 分析SQLite页面结构",
                "5. 使用工具箱上传.db文件自动分析"
            ],
            "tool_commands": [
                {"cmd": "sqlite3 database.db '.schema'", "desc": "查看表结构"},
                {"cmd": "sqlite3 database.db '.tables'", "desc": "列出所有表"},
                {"cmd": "sqlite3 database.db 'SELECT * FROM users;'", "desc": "查看数据"},
                {"cmd": "strings database.db | grep -i flag", "desc": "直接搜索flag"},
                {"cmd": "sqlite3 database.db 'SELECT sql FROM sqlite_master;'", "desc": "查看建表语句"},
            ]
        },
        8: {
            "title": "证据链与报告撰写",
            "description": "规范的电子证据收集和取证报告撰写",
            "steps": [
                "1. 计算原始证据哈希(收集前)",
                "2. 使用写保护设备创建镜像",
                "3. 计算镜像哈希(收集后)并比对",
                "4. 记录操作步骤和时间线",
                "5. 撰写取证报告(含哈希值、时间戳、发现)"
            ],
            "tool_commands": [
                {"cmd": "sha256sum original_evidence.dd > hash_before.txt", "desc": "收集前哈希"},
                {"cmd": "dd if=/dev/sda of=image.dd bs=4M", "desc": "创建镜像"},
                {"cmd": "sha256sum image.dd > hash_after.txt", "desc": "收集后哈希"},
                {"cmd": "diff hash_before.txt hash_after.txt", "desc": "比对哈希"},
                {"cmd": "fls -m / -r image.dd > body.txt && mactime -b body.txt > timeline.csv", "desc": "生成时间线"},
            ]
        },
    }

    if task_num not in tasks:
        return {"success": False, "error": f"未知任务编号: {task_num}，可选: 1-{len(tasks)}"}

    task = tasks[task_num]
    return {
        "success": True,
        "task_num": task_num,
        "title": task["title"],
        "description": task["description"],
        "steps": task["steps"],
        "commands": task["tool_commands"],
        "hint": "使用工具箱上传文件可自动完成大部分分析"
    }


def list_forensics_scenarios() -> dict:
    """列出所有取证场景"""
    scenarios = []
    for i in range(1, 9):
        task = competition_forensics_task(i)
        scenarios.append({
            "id": i,
            "title": task["title"],
            "description": task["description"]
        })
    return {"success": True, "scenarios": scenarios}

