"""压缩包分析模块 - 解压、弱密码爆破、伪加密检测"""
import zipfile
import os
import struct
import re
import tempfile
from solvers.common import find_flags_in_text, extract_strings, find_flags_in_strings

try:
    import rarfile
    # 配置 WinRAR 路径
    import shutil
    _unrar = shutil.which('unrar') or shutil.which('UnRAR')
    if not _unrar:
        # 尝试常见安装路径
        for p in [r'C:\Program Files\WinRAR\UnRAR.exe',
                  r'C:\Program Files (x86)\WinRAR\UnRAR.exe']:
            if os.path.exists(p):
                rarfile.UNRAR_TOOL = p
                break
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

# CTF常见弱密码字典
CTF_PASSWORDS = [
    "", "123456", "password", "admin", "root", "test", "1234", "123",
    "flag", "ctf", "secret", "passwd", "pass", "key", "1", "0",
    "12345", "123456789", "qwerty", "abc123", "111111", "1234567",
    "letmein", "welcome", "monkey", "dragon", "master", "666666",
    "888888", "password1", "password123", "admin123", "root123",
    "toor", "guest", "hello", "love", "sunshine", "princess",
    "football", "shadow", "michael", "computer", "internet",
    "superman", "1q2w3e4r", "qwerty123", "iloveyou", "1234567890",
    "000000", "1qaz2wsx", "abcdef", "a123456", "654321",
    "qwer1234", "zxcvbn", "asdfgh", "121212", "123qwe",
    "p@ssw0rd", "p@ssword", "pass@123", "admin@123",
    "P@ssw0rd", "Admin@123", "Root@123",
    "10086", "10010", "112233", "5201314", "1314520",
    "20240101", "20230101", "20250101", "19990101",
    "flag{}", "ctf{}", "key{}", "CTF", "FLAG", "ctf2024", "ctf2025",
    "f1ag", "fl4g", "fla9", "f1@g",
]


def _load_external_wordlist():
    """尝试从wordlists目录加载外部字典"""
    wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists', 'passwords.txt')
    if os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            pass
    return CTF_PASSWORDS


def _zip_needs_password(zf: zipfile.ZipFile) -> bool:
    """检查ZIP文件是否需要密码（兼容标准zipfile）"""
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            return True
    return False


def analyze_zip(filepath: str) -> dict:
    """分析ZIP文件结构并自动提取搜索flag"""
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            info_list = []
            has_password = False
            for info in zf.infolist():
                is_encrypted = info.flag_bits & 0x1 != 0
                if is_encrypted:
                    has_password = True
                info_list.append({
                    "filename": info.filename,
                    "file_size": info.file_size,
                    "compress_size": info.compress_size,
                    "compress_type": info.compress_type,
                    "needs_password": is_encrypted
                })

            comment = zf.comment.decode('utf-8', errors='ignore') if zf.comment else ""

            # 直接从ZIP中读取文件内容进行分析（不依赖文件系统）
            flags = []
            debug_info = []

            for info in zf.infolist():
                # 检查文件名
                if 'flag' in info.filename.lower():
                    flags.append(f"文件名匹配: {info.filename}")

                # 跳过目录
                if info.filename.endswith('/'):
                    continue

                try:
                    # 直接从ZIP读取文件内容
                    data = zf.read(info.filename)
                    debug_info.append(f"分析: {info.filename}, 大小: {len(data)}")

                    # 检查是否是PE文件
                    if data[:2] == b'MZ':
                        debug_info.append(f"  检测到PE文件: {info.filename}")

                        pe_success = False
                        # 写入临时文件后用reverse模块分析（pefile对文件路径的内存映射更可靠）
                        try:
                            from solvers.reverse import analyze_pe
                            with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
                                tmp.write(data)
                                tmp_path = tmp.name
                            try:
                                pe_result = analyze_pe(tmp_path)
                                if pe_result.get("flags"):
                                    flags.extend(pe_result["flags"])
                                    debug_info.append(f"  PE找到flag: {pe_result['flags']}")
                                    pe_success = True
                                else:
                                    debug_info.append(f"  PE提取到 {len(pe_result.get('strings', []))} 个字符串，未找到flag")
                            finally:
                                os.unlink(tmp_path)
                        except Exception as e:
                            debug_info.append(f"  PE分析失败: {str(e)}")

                        # 备用：直接从原始数据提取字符串
                        if not pe_success:
                            all_strings = extract_strings(data)
                            debug_info.append(f"  基础提取到 {len(all_strings)} 个字符串")
                            for s in all_strings:
                                found = find_flags_in_text(s)
                                if found:
                                    flags.extend(found)
                                    debug_info.append(f"  基础找到flag: {found}")
                    else:
                        # 非PE文件
                        all_strings = extract_strings(data)
                        for s in all_strings:
                            found = find_flags_in_text(s)
                            if found:
                                flags.extend(found)

                        # UTF-8解码搜索
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            found = find_flags_in_text(text)
                            if found:
                                flags.extend(found)
                        except Exception:
                            pass
                except Exception as e:
                    debug_info.append(f"  读取失败: {str(e)}")

            return {
                "success": True,
                "needs_password": has_password,
                "files": info_list,
                "file_count": len(info_list),
                "comment": comment,
                "pseudo_encrypted": _check_pseudo_encryption(filepath),
                "flags": list(set(flags)),
                "debug": debug_info
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _check_pseudo_encryption(filepath: str) -> dict:
    """检测ZIP伪加密"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # 查找本地文件头签名 PK\x03\x04
        local_headers = []
        pos = 0
        while True:
            idx = data.find(b'PK\x03\x04', pos)
            if idx == -1:
                break
            local_headers.append(idx)
            pos = idx + 1

        if not local_headers:
            return {"is_pseudo": False, "reason": "无本地文件头"}

        # 检查通用位标志（offset +6, 2 bytes）
        flags = struct.unpack('<H', data[local_headers[0] + 6:local_headers[0] + 8])[0]
        local_encrypted = flags & 0x1

        # 查找中央目录头签名 PK\x01\x02
        central_pos = data.find(b'PK\x01\x02')
        if central_pos == -1:
            return {"is_pseudo": False, "reason": "无中央目录"}

        central_flags = struct.unpack('<H', data[central_pos + 8:central_pos + 10])[0]
        central_encrypted = central_flags & 0x1

        if local_encrypted and not central_encrypted:
            return {"is_pseudo": True, "reason": "本地文件头标记加密但中央目录未标记，疑似伪加密"}
        elif local_encrypted and central_encrypted:
            return {"is_pseudo": False, "reason": "文件头和中央目录都标记为加密，真加密"}
        else:
            return {"is_pseudo": False, "reason": "未检测到加密标记"}
    except Exception as e:
        return {"is_pseudo": False, "error": str(e)}


def fix_pseudo_encryption(filepath: str) -> dict:
    """修复ZIP伪加密"""
    try:
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())

        # 修改本地文件头的加密标志位
        pos = 0
        fixed_count = 0
        while True:
            idx = data.find(b'PK\x03\x04', pos)
            if idx == -1:
                break
            flag_pos = idx + 6
            flags = struct.unpack('<H', data[flag_pos:flag_pos + 2])[0]
            if flags & 0x1:
                data[flag_pos] = data[flag_pos] & 0xFE
                fixed_count += 1
            pos = idx + 1

        output_path = filepath + '_fixed.zip'
        with open(output_path, 'wb') as f:
            f.write(data)

        return {"success": True, "fixed_count": fixed_count, "output_path": output_path}
    except Exception as e:
        return {"success": False, "error": str(e)}


def extract_zip(filepath: str, password: str = None, output_dir: str = None) -> dict:
    """解压ZIP文件"""
    if output_dir is None:
        output_dir = filepath + "_extracted"

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            file_list = zf.namelist()

            if _zip_needs_password(zf) and not password:
                return {
                    "success": False,
                    "needs_password": True,
                    "files": file_list,
                    "message": "压缩包需要密码"
                }

            pwd = password.encode() if password else None
            zf.extractall(output_dir, pwd=pwd)

            flags = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    if 'flag' in f.lower():
                        flags.append(f"文件名匹配: {fpath}")
                    try:
                        with open(fpath, 'r', errors='ignore') as fp:
                            content = fp.read(10000)
                            flags.extend(find_flags_in_text(content))
                    except Exception:
                        pass

            return {
                "success": True,
                "files": file_list,
                "output_dir": output_dir,
                "flags": flags,
                "file_count": len(file_list)
            }
    except zipfile.BadZipFile:
        return {"success": False, "error": "不是有效的ZIP文件"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def bruteforce_zip(filepath: str, wordlist: list[str] = None) -> dict:
    """ZIP弱密码字典爆破"""
    if wordlist is None:
        wordlist = _load_external_wordlist()

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            if not _zip_needs_password(zf):
                return {"success": True, "password": "", "message": "压缩包不需要密码"}

            test_file = zf.namelist()[0]

            for pwd in wordlist:
                try:
                    zf.read(test_file, pwd=pwd.encode() if pwd else None)
                    return {"success": True, "password": pwd, "message": f"密码破解成功: '{pwd}'"}
                except (RuntimeError, zipfile.BadZipFile, Exception):
                    continue

            # 尝试纯数字掩码爆破（4-6位）
            import itertools
            for length in range(4, 7):
                for digits in itertools.product('0123456789', repeat=length):
                    pwd = ''.join(digits)
                    try:
                        zf.read(test_file, pwd=pwd.encode())
                        return {"success": True, "password": pwd, "message": f"掩码爆破成功: '{pwd}'"}
                    except (RuntimeError, zipfile.BadZipFile, Exception):
                        continue

            return {"success": False, "message": f"字典爆破和数字掩码都失败了"}
    except zipfile.BadZipFile:
        return {"success": False, "error": "不是有效的ZIP文件"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def analyze_rar(filepath: str) -> dict:
    """分析RAR文件"""
    if not HAS_RARFILE:
        return {"success": False, "error": "rarfile模块未安装，无法处理RAR文件。请运行: pip install rarfile"}

    try:
        with rarfile.RarFile(filepath) as rf:
            files = []
            for info in rf.infolist():
                files.append({
                    "filename": info.filename,
                    "file_size": info.file_size,
                    "compress_size": info.compress_size,
                })
            return {
                "success": True,
                "needs_password": rf.needs_password(),
                "files": files,
                "file_count": len(files)
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def extract_rar(filepath: str, password: str = None, output_dir: str = None) -> dict:
    """解压RAR文件"""
    if not HAS_RARFILE:
        return {"success": False, "error": "rarfile模块未安装。请运行: pip install rarfile"}

    if output_dir is None:
        output_dir = filepath + "_extracted"

    try:
        with rarfile.RarFile(filepath) as rf:
            file_list = rf.namelist()

            if rf.needs_password() and not password:
                return {
                    "success": False,
                    "needs_password": True,
                    "files": file_list,
                    "message": "RAR压缩包需要密码"
                }

            pwd = password if password else None
            rf.extractall(output_dir, pwd=pwd)

            flags = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    if 'flag' in f.lower():
                        flags.append(f"文件名匹配: {fpath}")
                    try:
                        with open(fpath, 'r', errors='ignore') as fp:
                            content = fp.read(10000)
                            flags.extend(find_flags_in_text(content))
                    except Exception:
                        pass

            return {
                "success": True,
                "files": file_list,
                "output_dir": output_dir,
                "flags": flags,
                "file_count": len(file_list)
            }
    except rarfile.BadRarFile:
        return {"success": False, "error": "不是有效的RAR文件"}
    except rarfile.RarWrongPassword:
        return {"success": False, "error": "密码错误"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def bruteforce_rar(filepath: str, wordlist: list[str] = None) -> dict:
    """RAR弱密码字典爆破"""
    if not HAS_RARFILE:
        return {"success": False, "error": "rarfile模块未安装"}

    if wordlist is None:
        wordlist = _load_external_wordlist()

    try:
        with rarfile.RarFile(filepath) as rf:
            if not rf.needs_password():
                return {"success": True, "password": "", "message": "RAR压缩包不需要密码"}

            test_file = rf.namelist()[0]

            for pwd in wordlist:
                try:
                    rf.read(test_file, pwd=pwd)
                    return {"success": True, "password": pwd, "message": f"密码破解成功: '{pwd}'"}
                except (rarfile.RarWrongPassword, RuntimeError, Exception):
                    continue

            return {"success": False, "message": "字典爆破失败，未找到密码"}
    except Exception as e:
        return {"success": False, "error": str(e)}
