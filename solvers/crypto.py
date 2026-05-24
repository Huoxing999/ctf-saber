"""密码学/编码解题模块 - 自动识别编码、古典密码、MD5反查、多层解码"""
import base64
import hashlib
import re
import binascii
from solvers.common import find_flags_in_text

# 内置常见MD5字典（去重）
COMMON_MD5 = {
    "d41d8cd98f00b204e9800998ecf8427e": "",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e99a18c428cb38d5f260853678922e03": "abc123",
    "25d55ad283aa400af464c76d713c07ad": "12345678",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "5ebe2294ecd0e0f08eab7690d2a6ee69": "secret",
    "098f6bcd4621d373cade4e832627b4f6": "test",
    "6c569aabbf7775ef8fc570e228c16b98": "password1",
    "482c811da5d5b4bc6d497ffa98491e38": "password123",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "fcea920f7412b5da7be0cf42b8c93759": "1234567",
    "7c6a180b36896a6a88fd4c5e2c6c5f5d": "admin",
    "0192023a7bbd73250516f069df18b500": "admin123",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "25f9e794323b453885f5181f1b624d0b": "123456789",
    "3c59dc048e8850243be8079a5c74d079": "qwerty123",
    "f63f4fbc9f8c85d409f2f5d444db81a8": "letmein",
    "5d41402abc4b2a76b9719d911017c592": "hello",
    "89c0e4f4b2916df45ee5e29e99f10373": "flag",
    "37b4e2d82900d5e94b8da524fbeb43a5": "flag123",
    "06c4de07407a632b29b881ea9b898574": "1q2w3e4r",
    "6c9c30e1a91c85e1f0e0df8b0e4a4c3a": "qwertyuiop",
    "25f9e794323b453885f5181f1b624d0b": "123456789",
    "e807f1fcf82d132f9bb018ca6738a19f": "1234567890",
    "d93591bdf7860e1e4ee2fca799911215": "abcd1234",
    "098f6bcd4621d373cade4e832627b4f6": "test",
    "8c6976e5b5410415bde908bd4dee15df": "admin",
    "7c6a180b36896a6a88fd4c5e2c6c5f5d": "admin123",
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
}

HASH_TYPES = {
    32: "MD5",
    40: "SHA1",
    56: "SHA224",
    64: "SHA256",
    96: "SHA384",
    128: "SHA512",
}

# 培根密码表（A=00000, B=00001, ...）
BACON_MAP = {}
for i in range(26):
    BACON_MAP[format(i, '05b')] = chr(65 + i)


def identify_encoding(text: str) -> list[dict]:
    """自动识别文本可能的编码类型"""
    results = []
    text = text.strip()

    # Base64 检测
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
    if base64_pattern.match(text) and len(text) % 4 == 0 and len(text) >= 4:
        try:
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                results.append({"type": "Base64", "decoded": decoded, "confidence": 90})
        except Exception:
            pass

    # Base32 检测
    base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
    if base32_pattern.match(text) and len(text) >= 8:
        try:
            decoded = base64.b32decode(text).decode('utf-8', errors='ignore')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                results.append({"type": "Base32", "decoded": decoded, "confidence": 85})
        except Exception:
            pass

    # Hex 检测
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    if hex_pattern.match(text) and len(text) % 2 == 0 and len(text) >= 2:
        try:
            decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                results.append({"type": "Hex", "decoded": decoded, "confidence": 95})
        except Exception:
            pass
        try:
            decoded = bytes.fromhex(text).decode('gbk', errors='ignore')
            if any('一' <= c <= '鿿' for c in decoded):
                results.append({"type": "Hex(GBK)", "decoded": decoded, "confidence": 80})
        except Exception:
            pass

    # Binary 检测
    if re.match(r'^[01]+$', text) and len(text) >= 8 and len(text) % 8 == 0:
        try:
            decoded = ''.join(chr(int(text[i:i+8], 2)) for i in range(0, len(text), 8))
            if all(32 <= ord(c) < 127 for c in decoded):
                results.append({"type": "Binary", "decoded": decoded, "confidence": 90})
        except Exception:
            pass

    # URL编码 检测
    if '%' in text:
        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            if decoded != text:
                results.append({"type": "URL Encoding", "decoded": decoded, "confidence": 95})
        except Exception:
            pass

    # Unicode 检测
    if '\\u' in text:
        try:
            decoded = text.encode().decode('unicode_escape')
            if decoded != text:
                results.append({"type": "Unicode Escape", "decoded": decoded, "confidence": 85})
        except Exception:
            pass

    # Hash 检测
    if hex_pattern.match(text) and len(text) in HASH_TYPES:
        results.append({"type": "Hash", "hash_type": HASH_TYPES[len(text)], "confidence": 95})

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


def caesar_bruteforce(ciphertext: str) -> list[dict]:
    """凯撒密码全位移爆破"""
    results = []
    for shift in range(26):
        decrypted = ''
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                decrypted += chr((ord(ch) - base + shift) % 26 + base)
            else:
                decrypted += ch
        results.append({"shift": shift, "text": decrypted})
    return results


def rot13(text: str) -> str:
    """ROT13解码"""
    return caesar_bruteforce(text)[13]["text"]


def fence_decrypt(text: str) -> dict:
    """栅栏密码解密（尝试所有栏数）"""
    results = []
    text_clean = text.replace(' ', '')
    n = len(text_clean)

    for rails in range(2, min(n, 20)):
        # 创建栅栏矩阵
        fence = [['\n'] * n for _ in range(rails)]
        rail, direction = 0, 1

        for i in range(n):
            fence[rail][i] = '*'
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction

        # 填入密文
        idx = 0
        for r in range(rails):
            for c in range(n):
                if fence[r][c] == '*' and idx < n:
                    fence[r][c] = text_clean[idx]
                    idx += 1

        # 读取明文
        result = []
        rail, direction = 0, 1
        for i in range(n):
            result.append(fence[rail][i])
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction

        decoded = ''.join(result)
        score = _score_english(decoded)
        results.append({"rails": rails, "text": decoded, "score": score})

    results.sort(key=lambda x: x["score"], reverse=True)
    return {"results": results[:5]}


def vigenere_decrypt(ciphertext: str, key: str) -> dict:
    """Vigenere密码解密"""
    result = []
    key_idx = 0

    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % len(key)].upper()) - ord('A')
            decrypted = chr((ord(ch) - base - k) % 26 + base)
            result.append(decrypted)
            key_idx += 1
        else:
            result.append(ch)

    return {"decrypted": ''.join(result), "key": key}


def bacon_decrypt(text: str) -> dict:
    """培根密码解密（支持A/B和a/b格式）"""
    # 标准化：将a/b转为0/1
    text_clean = text.upper().replace(' ', '')
    if all(c in 'AB' for c in text_clean):
        binary = text_clean.replace('A', '0').replace('B', '1')
    elif all(c in '01' for c in text_clean):
        binary = text_clean
    else:
        return {"success": False, "error": "不是有效的培根密码（仅支持A/B或0/1格式）"}

    # 每5位一组解码
    result = []
    for i in range(0, len(binary) - 4, 5):
        chunk = binary[i:i+5]
        if chunk in BACON_MAP:
            result.append(BACON_MAP[chunk])

    decoded = ''.join(result)
    return {"success": True, "decrypted": decoded, "binary": binary}


def atbash_decrypt(text: str) -> dict:
    """Atbash密码解密（A↔Z, B↔Y, ...）"""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return {"decrypted": ''.join(result)}


def _score_english(text: str) -> float:
    """英文文本评分"""
    freq = {'e': 13, 't': 9, 'a': 8, 'o': 7, 'i': 7, 'n': 7, 's': 6, 'h': 6, 'r': 6}
    score = 0
    text_lower = text.lower()
    for ch, weight in freq.items():
        score += text_lower.count(ch) * weight
    return score


def md5_reverse(hash_str: str) -> dict:
    """MD5反查（查内置字典 + 暴力枚举）"""
    hash_str = hash_str.strip().lower()
    if len(hash_str) != 32:
        return {"found": False, "error": "不是有效的MD5哈希（长度应为32）"}

    if hash_str in COMMON_MD5:
        return {"found": True, "hash": hash_str, "plaintext": COMMON_MD5[hash_str]}

    # 暴力枚举数字
    for i in range(100000):
        if hashlib.md5(str(i).encode()).hexdigest() == hash_str:
            return {"found": True, "hash": hash_str, "plaintext": str(i)}

    # 常见密码+数字后缀
    common_words = ['flag', 'ctf', 'key', 'admin', 'root', 'test', 'pass', 'secret',
                    '123456', 'password', 'qwerty', 'abc123', 'letmein', 'welcome',
                    'monkey', 'dragon', 'master', 'hello', 'love', 'sunshine']
    for word in common_words:
        if hashlib.md5(word.encode()).hexdigest() == hash_str:
            return {"found": True, "hash": hash_str, "plaintext": word}
        for i in range(100):
            candidate = f"{word}{i}"
            if hashlib.md5(candidate.encode()).hexdigest() == hash_str:
                return {"found": True, "hash": hash_str, "plaintext": candidate}

    return {"found": False, "message": "内置字典未找到，可能需要更大的字典"}


def hash_identify(text: str) -> dict:
    """识别哈希类型"""
    text = text.strip()
    results = []
    if re.match(r'^[0-9a-fA-F]+$', text):
        length = len(text)
        if length in HASH_TYPES:
            results.append({"type": HASH_TYPES[length], "length": length})
        else:
            results.append({"type": f"Unknown hex string (length={length})", "length": length})

    if text.startswith('$2') and len(text) == 60:
        results.append({"type": "bcrypt", "length": len(text)})

    return {"hashes": results, "input": text}


def multi_decode(text: str) -> dict:
    """多层编码自动解码（尝试多种组合）"""
    results = []
    current = text.strip()

    for layer in range(5):
        found = False

        # Base64
        try:
            decoded = base64.b64decode(current).decode('utf-8', errors='ignore')
            if decoded and decoded != current and all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                results.append({"layer": layer + 1, "method": "Base64", "result": decoded})
                current = decoded
                found = True
                continue
        except Exception:
            pass

        # Base32
        try:
            decoded = base64.b32decode(current).decode('utf-8', errors='ignore')
            if decoded and decoded != current and all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                results.append({"layer": layer + 1, "method": "Base32", "result": decoded})
                current = decoded
                found = True
                continue
        except Exception:
            pass

        # Hex
        try:
            decoded = bytes.fromhex(current.replace(' ', '')).decode('utf-8', errors='ignore')
            if decoded and decoded != current and all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                results.append({"layer": layer + 1, "method": "Hex", "result": decoded})
                current = decoded
                found = True
                continue
        except Exception:
            pass

        # URL decode
        try:
            from urllib.parse import unquote
            decoded = unquote(current)
            if decoded != current:
                results.append({"layer": layer + 1, "method": "URL Decode", "result": decoded})
                current = decoded
                found = True
                continue
        except Exception:
            pass

        # Unicode decode
        if '\\u' in current:
            try:
                decoded = current.encode().decode('unicode_escape')
                if decoded != current:
                    results.append({"layer": layer + 1, "method": "Unicode", "result": decoded})
                    current = decoded
                    found = True
                    continue
            except Exception:
                pass

        if not found:
            break

    if not results:
        results.append({"layer": 0, "method": "None", "result": "未识别到已知编码格式"})

    return {"layers": results, "final_result": current}
