"""公共工具模块 - 提取各solver重复使用的功能"""
import re
import os

# Flag搜索正则（各模块共用）
FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'key\{[^}]+\}', re.IGNORECASE),
    re.compile(r'DBAPP\{[^}]+\}', re.IGNORECASE),
    re.compile(r'FLAG\{[^}]+\}'),
    re.compile(r'CTF\{[^}]+\}'),
    re.compile(r'hctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'bugku\{[^}]+\}', re.IGNORECASE),
    re.compile(r'pikachu\{[^}]+\}', re.IGNORECASE),
    re.compile(r'dasctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'nctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'sctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'wctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'xctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'f4n9\{[^}]+\}', re.IGNORECASE),
    re.compile(r'f1ag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'SECRET\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ANSWER\{[^}]+\}', re.IGNORECASE),
]

FLAG_PATTERN_STRINGS = [p.pattern for p in FLAG_PATTERNS]


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """从二进制数据中提取可打印字符串"""
    result = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append(''.join(current))
            current = []
    if len(current) >= min_len:
        result.append(''.join(current))
    return result


def find_flags_in_text(text: str) -> list[str]:
    """在任意文本中搜索flag格式字符串"""
    flags = []
    for pattern in FLAG_PATTERNS:
        matches = pattern.findall(text)
        flags.extend(matches)
    return list(set(flags))


def find_flags_in_strings(strings: list[str]) -> list[str]:
    """从字符串列表中搜索flag"""
    flags = []
    for s in strings:
        flags.extend(find_flags_in_text(s))
    return list(set(flags))


def success_response(**kwargs) -> dict:
    """构造成功响应"""
    return {"success": True, **kwargs}


def error_response(message: str, **kwargs) -> dict:
    """构造错误响应"""
    return {"success": False, "error": message, **kwargs}


def read_file_bytes(filepath: str) -> bytes:
    """安全读取文件字节"""
    with open(filepath, 'rb') as f:
        return f.read()


def get_file_size(filepath: str) -> int:
    """获取文件大小（不读取文件内容）"""
    return os.path.getsize(filepath)
