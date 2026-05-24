"""图片/音频隐写分析模块"""
import os
import re
import struct
from PIL import Image
from solvers.common import find_flags_in_text, extract_strings, get_file_size


def analyze_image(filepath: str) -> dict:
    """分析图片文件，提取隐藏信息"""
    results = {"strings": [], "flags": [], "metadata": {}, "lsb": None}

    with open(filepath, 'rb') as f:
        data = f.read()

    # 提取可打印字符串
    strings = extract_strings(data, min_len=4)
    results["strings"] = strings[:500]
    results["flags"] = find_flags_in_text(''.join(strings))

    # 检查文件尾部附加数据
    tail_strings = extract_strings(data[-1000:], min_len=4)
    results["tail_strings"] = tail_strings

    # 图片元数据
    try:
        img = Image.open(filepath)
        results["metadata"] = {
            "format": img.format,
            "size": img.size,
            "mode": img.mode,
        }
        if hasattr(img, '_getexif') and img._getexif():
            exif = img._getexif()
            results["exif"] = {str(k): str(v) for k, v in exif.items() if isinstance(v, (str, int, float))}
    except Exception as e:
        results["metadata"]["error"] = str(e)

    return results


def extract_lsb(filepath: str) -> dict:
    """LSB隐写提取"""
    try:
        img = Image.open(filepath)
        pixels = list(img.getdata())

        bits = []
        for pixel in pixels[:50000]:
            if isinstance(pixel, int):
                bits.append(pixel & 1)
            else:
                for channel in pixel[:3]:
                    bits.append(channel & 1)

        extracted = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            if byte == 0:
                break
            extracted.append(byte)

        text = extracted.decode('utf-8', errors='ignore')
        flags = find_flags_in_text(text)

        return {
            "success": True,
            "extracted_text": text[:2000],
            "flags": flags,
            "bits_extracted": len(bits)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_file_signature(filepath: str) -> dict:
    """检查文件真实类型（可能改了扩展名）"""
    with open(filepath, 'rb') as f:
        header = f.read(16)

    signatures = {
        b'\x89PNG': "PNG图片",
        b'\xff\xd8\xff': "JPEG图片",
        b'GIF87a': "GIF图片(v87a)",
        b'GIF89a': "GIF图片(v89a)",
        b'PK\x03\x04': "ZIP压缩包",
        b'Rar!\x1a\x07': "RAR压缩包",
        b'\x7fELF': "ELF可执行文件",
        b'MZ': "Windows PE可执行文件",
        b'%PDF': "PDF文档",
        b'\x00\x00\x01\x00': "ICO图标",
        b'BM': "BMP图片",
        b'RIFF': "RIFF容器(WebP/AVI等)",
        b'\xca\xfebabe': "Java Class文件",
        b'\xfe\xed\xfa': "Mach-O可执行文件",
    }

    detected = "未知类型"
    for sig, name in signatures.items():
        if header.startswith(sig):
            detected = name
            break

    with open(filepath, 'rb') as f:
        f.seek(-32, 2)
        tail = f.read()

    return {
        "header_hex": header.hex(),
        "detected_type": detected,
        "tail_hex": tail.hex(),
        "file_size": get_file_size(filepath)
    }


def binwalk_scan(filepath: str) -> dict:
    """扫描文件中嵌入的其他文件（简易binwalk）"""
    with open(filepath, 'rb') as f:
        data = f.read()

    signatures = [
        (b'\x89PNG', "PNG图片"),
        (b'\xff\xd8\xff', "JPEG图片"),
        (b'GIF87a', "GIF87a"),
        (b'GIF89a', "GIF89a"),
        (b'PK\x03\x04', "ZIP压缩包"),
        (b'Rar!\x1a\x07', "RAR压缩包"),
        (b'\x7fELF', "ELF文件"),
        (b'MZ', "PE文件"),
        (b'%PDF', "PDF文档"),
        (b'\x00\x00\x01\x00', "ICO图标"),
        (b'BM', "BMP图片"),
        (b'RIFF', "RIFF容器"),
        (b'ID3', "MP3音频"),
        (b'\x1a\x45\xdf\xa3', "MKV/WebM视频"),
        (b'\x42\x5a\x68', "BZ2压缩"),
        (b'\x1f\x8b', "GZIP压缩"),
        (b'\xfd7zXZ', "XZ压缩"),
    ]

    found = []
    for sig, name in signatures:
        pos = 0
        while True:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            if idx > 0:  # 跳过文件头部的签名
                found.append({"offset": hex(idx), "type": name, "offset_dec": idx})
            pos = idx + len(sig)

    # 提取嵌入的文件
    extracted = []
    for item in found:
        offset = item["offset_dec"]
        # 尝试提取（取到下一个签名或文件末尾）
        end = len(data)
        for sig, _ in signatures:
            next_pos = data.find(sig, offset + 4)
            if next_pos != -1 and next_pos < end:
                end = next_pos
        embedded_data = data[offset:end]
        if len(embedded_data) > 100:
            output_path = f"{filepath}_embedded_{offset}.{item['type'].split('(')[0].lower()}"
            try:
                with open(output_path, 'wb') as f:
                    f.write(embedded_data)
                extracted.append({"path": output_path, "size": len(embedded_data)})
            except Exception:
                pass

    return {
        "success": True,
        "found": found,
        "extracted": extracted,
        "total_signatures": len(found)
    }


def analyze_png_chunks(filepath: str) -> dict:
    """分析PNG IDAT块异常"""
    with open(filepath, 'rb') as f:
        data = f.read()

    if not data.startswith(b'\x89PNG'):
        return {"success": False, "error": "不是PNG文件"}

    chunks = []
    pos = 8  # 跳过PNG签名
    while pos < len(data) - 12:
        length = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
        chunks.append({
            "type": chunk_type,
            "offset": pos,
            "length": length
        })
        pos += 12 + length

    # 检查异常
    anomalies = []
    idat_chunks = [c for c in chunks if c["type"] == "IDAT"]
    if len(idat_chunks) > 0:
        sizes = [c["length"] for c in idat_chunks]
        avg_size = sum(sizes) / len(sizes)
        for c in idat_chunks:
            if c["length"] < avg_size * 0.1:
                anomalies.append(f"IDAT块异常小: offset={c['offset']}, size={c['length']}")

    return {
        "success": True,
        "chunks": chunks,
        "total_chunks": len(chunks),
        "idat_count": len(idat_chunks),
        "anomalies": anomalies
    }


def analyze_gif_frames(filepath: str) -> dict:
    """GIF逐帧分析"""
    try:
        img = Image.open(filepath)
        if img.format != 'GIF':
            return {"success": False, "error": "不是GIF文件"}

        frames = []
        frame_idx = 0
        try:
            while True:
                frame_data = list(img.convert('RGB').getdata())
                # 提取LSB
                bits = []
                for pixel in frame_data[:5000]:
                    for channel in pixel[:3]:
                        bits.append(channel & 1)

                extracted = bytearray()
                for i in range(0, len(bits) - 7, 8):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | bits[i + j]
                    if byte == 0:
                        break
                    extracted.append(byte)

                text = extracted.decode('utf-8', errors='ignore')
                flags = find_flags_in_text(text)

                frames.append({
                    "frame": frame_idx,
                    "size": img.size,
                    "extracted_text": text[:200],
                    "flags": flags
                })
                frame_idx += 1
                img.seek(img.tell() + 1)
        except EOFError:
            pass

        return {
            "success": True,
            "total_frames": frame_idx,
            "frames": frames[:20]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def analyze_audio(filepath: str) -> dict:
    """音频隐写分析（WAV LSB提取）"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        results = {"strings": [], "flags": []}

        # 提取可打印字符串
        strings = extract_strings(data, min_len=4)
        results["strings"] = strings[:200]
        results["flags"] = find_flags_in_text(''.join(strings))

        # WAV LSB分析
        if data[:4] == b'RIFF' and data[8:12] == b'WAVE':
            results["format"] = "WAV"
            # 解析WAV头
            if len(data) >= 44:
                channels = struct.unpack('<H', data[22:24])[0]
                sample_rate = struct.unpack('<I', data[24:28])[0]
                bits_per_sample = struct.unpack('<H', data[34:36])[0]
                results["wav_info"] = {
                    "channels": channels,
                    "sample_rate": sample_rate,
                    "bits_per_sample": bits_per_sample
                }

                # LSB提取
                if bits_per_sample == 16 and len(data) > 44:
                    samples = struct.unpack(f'<{len(data)//2 - 22}h', data[44:])
                    bits = [s & 1 for s in samples[:40000]]
                    extracted = bytearray()
                    for i in range(0, len(bits) - 7, 8):
                        byte = 0
                        for j in range(8):
                            byte = (byte << 1) | bits[i + j]
                        if byte == 0:
                            break
                        extracted.append(byte)
                    text = extracted.decode('utf-8', errors='ignore')
                    results["lsb_text"] = text[:2000]
                    results["flags"].extend(find_flags_in_text(text))
        else:
            results["format"] = "未知音频格式"

        results["flags"] = list(set(results["flags"]))
        return results
    except Exception as e:
        return {"success": False, "error": str(e)}
