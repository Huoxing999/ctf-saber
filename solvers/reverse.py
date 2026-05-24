"""逆向工程解题模块 - PE/ELF分析、字符串提取、异或爆破"""
import struct
from solvers.common import (
    FLAG_PATTERNS, extract_strings, find_flags_in_text, find_flags_in_strings,
    success_response, error_response
)


def analyze_pe(filepath: str) -> dict:
    """分析PE/ELF文件，提取关键信息"""
    results = {"strings": [], "flags": [], "resources": [], "sections": [], "imports": []}

    with open(filepath, 'rb') as f:
        header = f.read(4)

    # 检测文件类型
    if header[:2] == b'MZ':
        return _analyze_pe_file(filepath, results)
    elif header[:4] == b'\x7fELF':
        return _analyze_elf_file(filepath, results)
    else:
        return _analyze_generic(filepath, results)


def _analyze_pe_file(filepath: str, results: dict) -> dict:
    """分析PE文件"""
    try:
        import pefile
        pe = pefile.PE(filepath)

        for sec in pe.sections:
            name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
            results["sections"].append({
                "name": name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": round(sec.get_entropy(), 2)
            })

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.name:
                    results["resources"].append(str(entry.name))
                if hasattr(entry, 'directory'):
                    for sub in entry.directory.entries:
                        if hasattr(sub, 'directory'):
                            for res in sub.directory.entries:
                                data_rva = res.data.struct.OffsetToData
                                size = res.data.struct.Size
                                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                strings_in_res = extract_strings(data)
                                results["resources"].extend(strings_in_res[:20])

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        results["imports"].append(f"{dll_name}!{imp.name.decode('utf-8', errors='ignore')}")

        raw_data = pe.get_memory_mapped_image()
        all_strings = extract_strings(raw_data)
        results["strings"] = all_strings[:500]
        results["flags"] = find_flags_in_strings(all_strings)
        pe.close()

    except ImportError:
        results = _analyze_generic(filepath, results)
        results["note"] = "pefile未安装，使用基础分析模式"
    except Exception as e:
        results["error"] = str(e)
        results = _analyze_generic(filepath, results)

    return results


def _analyze_elf_file(filepath: str, results: dict) -> dict:
    """分析ELF文件（基础模式）"""
    with open(filepath, 'rb') as f:
        data = f.read()

    # ELF头解析
    if len(data) >= 20:
        ei_class = data[4]  # 1=32bit, 2=64bit
        ei_data = data[5]   # 1=LE, 2=BE
        e_type = struct.unpack('<H' if ei_data == 1 else '>H', data[16:18])[0]
        type_names = {1: "REL (可重定位)", 2: "EXEC (可执行)", 3: "DYN (共享对象)", 4: "CORE"}
        results["elf_info"] = {
            "class": "ELF64" if ei_class == 2 else "ELF32",
            "endian": "Little Endian" if ei_data == 1 else "Big Endian",
            "type": type_names.get(e_type, f"Unknown ({e_type})")
        }

    all_strings = extract_strings(data)
    results["strings"] = all_strings[:500]
    results["flags"] = find_flags_in_strings(all_strings)
    return results


def _analyze_generic(filepath: str, results: dict) -> dict:
    """通用二进制文件分析"""
    with open(filepath, 'rb') as f:
        data = f.read()
    all_strings = extract_strings(data)
    results["strings"] = all_strings[:500]
    results["flags"] = find_flags_in_strings(all_strings)
    return results


def xor_bruteforce(data: bytes, max_key_len: int = 4) -> dict:
    """异或爆破，尝试单字节到多字节key"""
    results = []
    sample = data[:500]

    # 单字节爆破
    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in sample)
        if is_meaningful(decrypted):
            text = decrypted.decode('utf-8', errors='ignore')
            score = score_text(text)
            results.append({"key": hex(key), "key_len": 1, "text": text[:200], "score": score})

    # 双字节爆破
    if max_key_len >= 2:
        for b1 in range(256):
            for b2 in range(256):
                key = bytes([b1, b2])
                if key == b'\x00\x00':
                    continue
                decrypted = bytes(sample[i] ^ key[i % 2] for i in range(len(sample)))
                if is_meaningful(decrypted):
                    text = decrypted.decode('utf-8', errors='ignore')
                    score = score_text(text)
                    if score > 50:
                        results.append({"key": key.hex(), "key_len": 2, "text": text[:200], "score": score})

    # 三字节爆破（高频组合）
    if max_key_len >= 3:
        common_3byte = [
            b'\x00\x00\x01', b'\x01\x01\x01', b'\xff\xff\xff',
            b'\xaa\xbb\xcc', b'\x01\x02\x03', b'\x12\x34\x56',
        ]
        for key in common_3byte:
            decrypted = bytes(sample[i] ^ key[i % 3] for i in range(len(sample)))
            if is_meaningful(decrypted):
                text = decrypted.decode('utf-8', errors='ignore')
                score = score_text(text)
                results.append({"key": key.hex(), "key_len": 3, "text": text[:200], "score": score})

    results.sort(key=lambda x: x["score"], reverse=True)

    flags = []
    for r in results[:10]:
        flags.extend(find_flags_in_text(r["text"]))

    return {"top_results": results[:10], "flags": list(set(flags))}


def is_meaningful(data: bytes) -> bool:
    """判断解密结果是否有意义"""
    if len(data) == 0:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) > 0.7


def score_text(text: str) -> float:
    """给解密文本打分（英文频率分析）"""
    freq = {'e': 13, 't': 9, 'a': 8, 'o': 7, 'i': 7, 'n': 7, 's': 6, 'h': 6, 'r': 6}
    score = 0
    text_lower = text.lower()
    for ch, weight in freq.items():
        score += text_lower.count(ch) * weight
    for pattern in FLAG_PATTERNS:
        if pattern.search(text):
            score += 1000
    return score
