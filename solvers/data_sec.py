"""数据安全模块 - 校验、脱敏、编解码、哈希、敏感扫描、分类分级、Excel处理、竞赛清洗"""
import re
import csv
import hashlib
import io
import datetime
import base64
import urllib.parse
import os


# pandas 延迟导入
def _get_pd():
    try:
        import pandas as pd
        return pd
    except ImportError:
        return None


def luhn_check(number: str) -> dict:
    """Luhn算法校验（信用卡号等）"""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 2:
        return {"valid": False, "error": "数字太短"}

    checksum = 0
    rev = digits[::-1]
    for i, d in enumerate(rev):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d

    return {
        "valid": checksum % 10 == 0,
        "number": number,
        "checksum": checksum,
        "mod10": checksum % 10
    }


def identify_card_type(number: str) -> dict:
    """识别银行卡类型"""
    digits = re.sub(r'\D', '', number)

    card_types = []
    if re.match(r'^4\d{12,18}$', digits):
        card_types.append("VISA")
    if re.match(r'^5[1-5]\d{14}$', digits) or re.match(r'^2(2[2-9]|[3-6]\d|7[01])\d{12}$', digits):
        card_types.append("MasterCard")
    if re.match(r'^3[47]\d{13}$', digits):
        card_types.append("American Express")
    if re.match(r'^62\d{14,17}$', digits):
        card_types.append("银联(UnionPay)")
    if re.match(r'^35(2[89]|[3-8]\d)\d{12}$', digits):
        card_types.append("JCB")
    if re.match(r'^6011\d{12}$', digits) or re.match(r'^65\d{14}$', digits):
        card_types.append("Discover")
    if re.match(r'^3(?:0[0-5]|[68]\d)\d{11}$', digits):
        card_types.append("Diners Club")

    luhn = luhn_check(digits)

    return {
        "number": digits,
        "card_types": card_types if card_types else ["未知卡种"],
        "luhn_valid": luhn["valid"],
        "length": len(digits)
    }


def validate_visa(number: str) -> dict:
    """校验VISA卡号"""
    digits = re.sub(r'\D', '', number)
    issues = []
    if len(digits) != 16:
        issues.append(f"长度应为16位，当前{len(digits)}位")
    if not digits.startswith('4'):
        issues.append("VISA卡号应以4开头")
    luhn = luhn_check(digits)
    if not luhn["valid"]:
        issues.append("Luhn校验不通过")

    return {
        "valid": len(issues) == 0,
        "number": digits,
        "issues": issues,
        "luhn_valid": luhn["valid"]
    }


def validate_id_card(id_number: str) -> dict:
    """中国身份证号校验"""
    id_number = id_number.strip()
    issues = []

    if len(id_number) != 18:
        issues.append(f"长度应为18位，当前{len(id_number)}位")
        return {"valid": False, "id": id_number, "issues": issues}

    if not re.match(r'^[1-9]\d{5}', id_number[:6]):
        issues.append("地区码格式错误")

    current_year = datetime.datetime.now().year
    try:
        year = int(id_number[6:10])
        month = int(id_number[10:12])
        day = int(id_number[12:14])
        if not (1900 <= year <= current_year and 1 <= month <= 12 and 1 <= day <= 31):
            issues.append("出生日期无效")
    except ValueError:
        issues.append("出生日期格式错误")

    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = '10X98765432'
    try:
        total = sum(int(id_number[i]) * weights[i] for i in range(17))
        expected = check_codes[total % 11]
        if id_number[17].upper() != expected:
            issues.append(f"校验码错误，应为{expected}，实际为{id_number[17]}")
    except (ValueError, IndexError):
        issues.append("校验码计算失败")

    return {"valid": len(issues) == 0, "id": id_number, "issues": issues}


def clean_csv_data(csv_text: str, rules: dict = None) -> dict:
    """清洗CSV数据"""
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    total = len(rows)
    removed = []
    kept = []

    if rules is None:
        rules = {}

    for i, row in enumerate(rows):
        remove = False
        reason = ""

        if rules.get("no_empty"):
            for col in rules["no_empty"]:
                if col in row and (row[col] is None or row[col].strip() == ''):
                    remove = True
                    reason = f"字段'{col}'为空"
                    break

        if not remove and rules.get("range_checks"):
            for col, (min_val, max_val) in rules["range_checks"].items():
                if col in row:
                    try:
                        val = float(row[col])
                        if val < min_val or val > max_val:
                            remove = True
                            reason = f"字段'{col}'值{val}超出范围[{min_val},{max_val}]"
                            break
                    except ValueError:
                        remove = True
                        reason = f"字段'{col}'不是有效数字"
                        break

        if not remove and rules.get("format_checks"):
            for col, fmt in rules["format_checks"].items():
                if col in row and row[col]:
                    if fmt == "id_card":
                        result = validate_id_card(row[col])
                        if not result["valid"]:
                            remove = True
                            reason = f"身份证号校验失败: {', '.join(result['issues'])}"
                            break
                    elif fmt == "visa":
                        result = validate_visa(row[col])
                        if not result["valid"]:
                            remove = True
                            reason = f"VISA卡号校验失败: {', '.join(result['issues'])}"
                            break
                    elif fmt == "luhn":
                        result = luhn_check(row[col])
                        if not result["valid"]:
                            remove = True
                            reason = "Luhn校验不通过"
                            break

        if not remove and rules.get("dedup"):
            for prev_row in kept:
                if all(row.get(k) == prev_row.get(k) for k in rules["dedup"]):
                    remove = True
                    reason = "重复数据"
                    break

        if remove:
            removed.append({"row": i + 1, "data": row, "reason": reason})
        else:
            kept.append(row)

    return {
        "total": total,
        "kept": len(kept),
        "removed": len(removed),
        "removed_rows": removed[:50],
        "kept_data": kept[:100]
    }


def desensitize_amount(amount: float) -> dict:
    """金额脱敏（基于个位数字：奇数上浮3%，偶数下浮3%）"""
    last_digit = int(str(int(amount))[-1])
    if last_digit % 2 == 1:
        change = amount * 0.03
        new_amount = amount + change
        direction = "上浮3%"
    else:
        change = amount * 0.03
        new_amount = amount - change
        direction = "下浮3%"

    return {
        "original": amount,
        "desensitized": round(new_amount, 2),
        "direction": direction,
        "last_digit": last_digit,
        "formatted": f"{new_amount:.2f}"
    }


def desensitize_phone(phone: str) -> dict:
    """手机号脱敏：中间4位替换为****"""
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 11:
        masked = digits[:3] + '****' + digits[7:]
        return {"original": phone, "masked": masked, "type": "手机号"}
    return {"original": phone, "error": "不是有效手机号"}


def desensitize_id_card(id_number: str) -> dict:
    """身份证脱敏：保留前3后4"""
    if len(id_number) == 18:
        masked = id_number[:3] + '***********' + id_number[14:]
        return {"original": id_number, "masked": masked, "type": "身份证"}
    return {"original": id_number, "error": "不是有效身份证号"}


def desensitize_bank_card(card_number: str) -> dict:
    """银行卡脱敏：保留前6后4"""
    digits = re.sub(r'\D', '', card_number)
    if len(digits) >= 10:
        masked = digits[:6] + '*' * (len(digits) - 10) + digits[-4:]
        return {"original": card_number, "masked": masked, "type": "银行卡"}
    return {"original": card_number, "error": "卡号太短"}


def desensitize_email(email: str) -> dict:
    """邮箱脱敏：@前保留首尾字符"""
    if '@' in email:
        local, domain = email.split('@', 1)
        if len(local) > 2:
            masked = local[0] + '***' + local[-1] + '@' + domain
        else:
            masked = local[0] + '***@' + domain
        return {"original": email, "masked": masked, "type": "邮箱"}
    return {"original": email, "error": "不是有效邮箱"}


def auto_desensitize(text: str) -> dict:
    """自动识别并脱敏文本中的敏感信息"""
    results = []

    # 手机号
    phones = re.findall(r'1[3-9]\d{9}', text)
    for p in phones:
        results.append(desensitize_phone(p))

    # 身份证号
    ids = re.findall(r'[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]', text)
    for i in ids:
        results.append(desensitize_id_card(i))

    # 银行卡号（16-19位数字，更严格的匹配）
    cards = re.findall(r'\b[3-6]\d{15,18}\b', text)
    for c in cards:
        if luhn_check(c)["valid"]:
            results.append(desensitize_bank_card(c))

    # 邮箱
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    for e in emails:
        results.append(desensitize_email(e))

    return {"found": len(results), "results": results}


def compute_md5(text: str) -> str:
    """计算MD5"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()


# ============ 多算法哈希 ============

def compute_hash(text: str, algo: str = "md5") -> dict:
    """计算文本哈希值，支持md5/sha1/sha256/sha512"""
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    algo = algo.lower()
    if algo not in algos:
        return {"success": False, "error": f"不支持的算法: {algo}", "available": list(algos.keys())}
    h = algos[algo](text.encode('utf-8')).hexdigest()
    return {"success": True, "text": text, "algorithm": algo, "hash": h}


def file_hash(filepath: str, algo: str = "sha256") -> dict:
    """计算文件哈希值（完整性校验）"""
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    algo = algo.lower()
    if algo not in algos:
        return {"success": False, "error": f"不支持的算法: {algo}"}
    try:
        h = algos[algo]()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return {
            "success": True,
            "file": os.path.basename(filepath),
            "size": os.path.getsize(filepath),
            "algorithm": algo,
            "hash": h.hexdigest()
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============ Base64 编解码 ============

def base64_encode(text: str) -> dict:
    """Base64编码"""
    try:
        encoded = base64.b64encode(text.encode('utf-8')).decode('ascii')
        return {"success": True, "original": text, "encoded": encoded, "mode": "encode"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def base64_decode(text: str) -> dict:
    """Base64解码"""
    try:
        # 补齐=号
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        decoded = base64.b64decode(text).decode('utf-8', errors='replace')
        return {"success": True, "original": text, "decoded": decoded, "mode": "decode"}
    except Exception as e:
        return {"success": False, "error": f"Base64解码失败: {str(e)}"}


# ============ URL 编解码 ============

def url_encode(text: str) -> dict:
    """URL编码"""
    encoded = urllib.parse.quote(text, safe='')
    return {"success": True, "original": text, "encoded": encoded, "mode": "encode"}


def url_decode(text: str) -> dict:
    """URL解码"""
    try:
        decoded = urllib.parse.unquote(text)
        return {"success": True, "original": text, "decoded": decoded, "mode": "decode"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============ Hex 编解码 ============

def hex_encode(text: str) -> dict:
    """文本转十六进制"""
    hex_str = text.encode('utf-8').hex()
    return {"success": True, "original": text, "hex": hex_str, "mode": "encode"}


def hex_decode(hex_str: str) -> dict:
    """十六进制转文本"""
    try:
        hex_str = hex_str.replace(' ', '').replace('0x', '').replace('\\x', '')
        decoded = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
        return {"success": True, "original": hex_str, "decoded": decoded, "mode": "decode"}
    except Exception as e:
        return {"success": False, "error": f"Hex解码失败: {str(e)}"}


# ============ 敏感数据扫描 ============

SENSITIVE_PATTERNS = {
    "手机号": re.compile(r'1[3-9]\d{9}'),
    "身份证号": re.compile(r'[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]'),
    "银行卡号": re.compile(r'\b[3-6]\d{15,18}\b'),
    "邮箱地址": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "IP地址": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "MAC地址": re.compile(r'[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}'),
    "密码字段": re.compile(r'(?:password|passwd|pwd|密码|口令)\s*[:=]\s*\S+', re.IGNORECASE),
    "密钥字段": re.compile(r'(?:key|secret|token|密钥|令牌)\s*[:=]\s*\S+', re.IGNORECASE),
    "内网地址": re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
}


def scan_sensitive(text: str) -> dict:
    """扫描文本中的敏感信息"""
    findings = {}
    total = 0
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[name] = {"count": len(matches), "samples": list(set(matches))[:10]}
            total += len(matches)

    # 风险等级
    if total == 0:
        level = "安全"
    elif total <= 3:
        level = "低风险"
    elif total <= 10:
        level = "中风险"
    else:
        level = "高风险"

    return {
        "success": True,
        "total_found": total,
        "risk_level": level,
        "findings": findings
    }


# ============ 数据分类分级 ============

DATA_LEVELS = {
    "L1-公开": ["姓名", "邮箱地址"],
    "L2-内部": ["IP地址", "MAC地址"],
    "L3-机密": ["手机号", "身份证号", "银行卡号"],
    "L4-绝密": ["密码字段", "密钥字段", "内网地址"],
}


def classify_data(text: str) -> dict:
    """对数据进行分类分级标注"""
    scan = scan_sensitive(text)
    if not scan["success"]:
        return scan

    classification = {}
    for data_type, info in scan["findings"].items():
        level = "未分类"
        for lv, types in DATA_LEVELS.items():
            if data_type in types:
                level = lv
                break
        classification[data_type] = {
            "level": level,
            "count": info["count"],
            "samples": info["samples"][:5]
        }

    # 整体风险等级
    levels_found = set(v["level"] for v in classification.values())
    if "L4-绝密" in levels_found:
        overall = "L4-绝密"
    elif "L3-机密" in levels_found:
        overall = "L3-机密"
    elif "L2-内部" in levels_found:
        overall = "L2-内部"
    elif "L1-公开" in levels_found:
        overall = "L1-公开"
    else:
        overall = "无敏感数据"

    return {
        "success": True,
        "overall_level": overall,
        "total_items": scan["total_found"],
        "classification": classification
    }


# ============ 密码强度检测 ============

def check_password_strength(password: str) -> dict:
    """评估密码强度"""
    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("密码长度至少8位")

    if len(password) >= 12:
        score += 1

    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("包含小写字母")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append("包含大写字母")

    if re.search(r'\d', password):
        score += 1
    else:
        suggestions.append("包含数字")

    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]', password):
        score += 1
    else:
        suggestions.append("包含特殊字符")

    # 常见弱密码检测
    weak_passwords = ['123456', 'password', 'admin', 'root', '123456789', 'qwerty',
                      '12345678', '111111', '1234567890', '1234567', 'abc123']
    if password.lower() in weak_passwords:
        score = 0
        suggestions = ["这是常见弱密码，极易被破解"]

    # 连续字符检测
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        suggestions.append("避免连续重复字符")

    score = max(0, min(score, 5))

    strength_labels = {0: "极弱", 1: "弱", 2: "一般", 3: "中等", 4: "强", 5: "非常强"}
    strength_colors = {0: "red", 1: "red", 2: "orange", 3: "yellow", 4: "green", 5: "darkgreen"}

    return {
        "success": True,
        "password": "*" * len(password),
        "length": len(password),
        "score": score,
        "strength": strength_labels[score],
        "color": strength_colors[score],
        "suggestions": suggestions
    }


# ============ 竞赛一键脱敏 ============

def competition_desensitize(csv_text: str, rules: dict = None) -> dict:
    """竞赛模式一键数据脱敏"""
    if rules is None:
        rules = {
            "phone": True,
            "id_card": True,
            "bank_card": True,
            "email": True,
            "name": True,
            "amount": True,
        }

    lines = csv_text.strip().split('\n')
    if not lines:
        return {"success": False, "error": "空数据"}

    headers = lines[0].split(',')
    result_lines = [lines[0]]
    stats = {"phone": 0, "id_card": 0, "bank_card": 0, "email": 0, "name": 0, "amount": 0}

    for line in lines[1:]:
        fields = line.split(',')
        new_fields = []
        for i, field in enumerate(fields):
            field = field.strip()
            header = headers[i].strip() if i < len(headers) else ""

            # 手机号
            if rules.get("phone") and re.match(r'^1[3-9]\d{9}$', field):
                new_fields.append(desensitize_phone(field)["masked"])
                stats["phone"] += 1
            # 身份证
            elif rules.get("id_card") and re.match(r'^\d{17}[\dXx]$', field):
                new_fields.append(desensitize_id_card(field)["masked"])
                stats["id_card"] += 1
            # 银行卡
            elif rules.get("bank_card") and re.match(r'^\d{16,19}$', field):
                new_fields.append(desensitize_bank_card(field)["masked"])
                stats["bank_card"] += 1
            # 邮箱
            elif rules.get("email") and '@' in field and '.' in field.split('@')[-1]:
                new_fields.append(desensitize_email(field)["masked"])
                stats["email"] += 1
            # 姓名
            elif rules.get("name") and re.match(r'^[一-龥]{2,4}$', field) and header in ("姓名", "name", "名字"):
                new_fields.append(field[0] + "*" * (len(field) - 1))
                stats["name"] += 1
            # 金额
            elif rules.get("amount") and header in ("金额", "amount", "余额", "balance"):
                try:
                    amt = float(field)
                    new_fields.append(desensitize_amount(amt)["formatted"])
                    stats["amount"] += 1
                except ValueError:
                    new_fields.append(field)
            else:
                new_fields.append(field)

        result_lines.append(','.join(new_fields))

    return {
        "success": True,
        "original_rows": len(lines) - 1,
        "stats": stats,
        "result": '\n'.join(result_lines)
    }


# ============ 从 data_cleaning 迁移的函数 ============

def desensitize_name(name: str) -> str:
    """姓名脱敏: 保留姓，其余用*"""
    if not name or len(name) < 2:
        return name
    return name[0] + "*" * (len(name) - 1)


def age_to_range(age: int) -> str:
    """年龄转5年区间"""
    start = (age // 5) * 5
    return f"{start}-{start + 4}"


def clean_data_preview(text: str) -> dict:
    """数据清洗预览 - 分析数据质量问题"""
    lines = text.strip().split('\n')
    if not lines:
        return {"success": False, "error": "空数据"}

    headers = [h.strip() for h in lines[0].split(',')]
    issues = {
        "null_rows": 0,
        "whitespace_issues": 0,
        "duplicate_rows": 0,
        "type_mismatches": [],
        "sample_issues": []
    }

    seen_rows = set()
    for i, line in enumerate(lines[1:], 2):
        fields = line.split(',')

        if any(f.strip() == '' or f.strip().lower() == 'null' for f in fields):
            issues["null_rows"] += 1
        if any(f != f.strip() for f in fields):
            issues["whitespace_issues"] += 1
        if line in seen_rows:
            issues["duplicate_rows"] += 1
        seen_rows.add(line)

        if len(issues["sample_issues"]) < 5:
            row_issues = []
            for j, f in enumerate(fields):
                if f.strip() == '':
                    row_issues.append(f"第{j+1}列为空")
                elif f != f.strip():
                    row_issues.append(f"第{j+1}列有多余空白")
            if row_issues:
                issues["sample_issues"].append({"row": i, "issues": row_issues})

    return {
        "success": True,
        "total_rows": len(lines) - 1,
        "columns": len(headers),
        "headers": headers,
        "issues": issues
    }


def parse_excel(filepath: str) -> dict:
    """解析Excel文件，返回所有sheet信息和数据预览"""
    pd = _get_pd()
    if pd is None:
        return {"success": False, "error": "需要安装pandas和openpyxl: pip install pandas openpyxl"}

    try:
        xls = pd.ExcelFile(filepath)
        sheets_info = {}
        for sheet_name in xls.sheet_names:
            df = pd.read_excel(xls, sheet_name=sheet_name)
            sheets_info[sheet_name] = {
                "columns": list(df.columns),
                "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
                "rows": len(df),
                "null_counts": df.isnull().sum().to_dict(),
                "preview": df.head(10).fillna("").to_dict(orient='records')
            }
        return {
            "success": True,
            "file": os.path.basename(filepath),
            "sheet_count": len(xls.sheet_names),
            "sheet_names": xls.sheet_names,
            "sheets": sheets_info
        }
    except Exception as e:
        return {"success": False, "error": f"解析Excel失败: {str(e)}"}


def excel_to_csv(filepath: str, sheet_name: str = None) -> dict:
    """将Excel指定sheet转为CSV文本"""
    pd = _get_pd()
    if pd is None:
        return {"success": False, "error": "需要安装pandas和openpyxl"}

    try:
        df = pd.read_excel(filepath, sheet_name=sheet_name or 0)
        csv_text = df.to_csv(index=False)
        return {
            "success": True,
            "sheet": sheet_name or "Sheet1",
            "columns": list(df.columns),
            "rows": len(df),
            "csv": csv_text
        }
    except Exception as e:
        return {"success": False, "error": f"转换失败: {str(e)}"}


def analyze_excel_quality(filepath: str) -> dict:
    """分析Excel数据质量问题"""
    pd = _get_pd()
    if pd is None:
        return {"success": False, "error": "需要安装pandas和openpyxl"}

    try:
        xls = pd.ExcelFile(filepath)
        all_issues = {}
        for sheet_name in xls.sheet_names:
            df = pd.read_excel(xls, sheet_name=sheet_name)
            issues = {
                "total_rows": len(df),
                "total_cols": len(df.columns),
                "null_rows": int(df.isnull().any(axis=1).sum()),
                "duplicate_rows": int(df.duplicated().sum()),
                "null_by_col": {},
                "type_issues": []
            }
            for col in df.columns:
                null_count = int(df[col].isnull().sum())
                if null_count > 0:
                    issues["null_by_col"][col] = null_count
                non_null = df[col].dropna()
                if len(non_null) > 0:
                    types = non_null.apply(type).nunique()
                    if types > 1:
                        issues["type_issues"].append(f"列'{col}'包含混合数据类型")
            all_issues[sheet_name] = issues
        return {"success": True, "sheets": all_issues}
    except Exception as e:
        return {"success": False, "error": f"分析失败: {str(e)}"}


def _read_data_file(filepath: str):
    """读取Excel或CSV文件，返回DataFrame"""
    pd = _get_pd()
    if pd is None:
        return None, "需要安装pandas和openpyxl"
    ext = os.path.splitext(filepath)[1].lower()
    try:
        if ext in ('.xlsx', '.xls'):
            df = pd.read_excel(filepath)
        else:
            df = pd.read_csv(filepath)
        return df, None
    except Exception as e:
        return None, f"读取文件失败: {str(e)}"


def competition_clean(filepath: str, table_type: str) -> dict:
    """一键竞赛清洗模式"""
    pd = _get_pd()
    if pd is None:
        return {"success": False, "error": "需要安装pandas: pip install pandas openpyxl"}

    df, err = _read_data_file(filepath)
    if df is None:
        return {"success": False, "error": err}

    original_count = len(df)
    removed_rows = []
    desensitized = {}
    warnings = []

    if table_type == "customer":
        df, removed, desc = _clean_customer_table(df, pd)
        removed_rows.extend(removed)
        desensitized["table_type"] = "客户表"
    elif table_type == "transaction":
        df, removed, desc = _clean_transaction_table(df, pd)
        removed_rows.extend(removed)
        desensitized["table_type"] = "交易表"
    elif table_type == "account":
        df, removed, desc = _clean_account_table(df, pd)
        removed_rows.extend(removed)
        desensitized["table_type"] = "账户表"
    else:
        return {"success": False, "error": f"不支持的表类型: {table_type}，可选: customer, transaction, account"}

    before_dedup = len(df)
    df = df.dropna(how='all')
    after_dropna = len(df)
    if before_dedup - after_dropna > 0:
        removed_rows.append({"reason": "整行为空", "count": before_dedup - after_dropna})

    df = df.drop_duplicates()
    after_dedup = len(df)
    if after_dropna - after_dedup > 0:
        removed_rows.append({"reason": "重复行", "count": after_dropna - after_dedup})

    result = {
        "success": True,
        "table_type": table_type,
        "original_rows": original_count,
        "cleaned_rows": len(df),
        "removed_total": original_count - len(df),
        "removed_details": removed_rows,
        "desensitized": desensitized,
        "preview": df.head(20).fillna("").to_dict(orient='records'),
        "columns": list(df.columns),
        "warnings": warnings
    }
    result["cleaned_csv"] = df.to_csv(index=False)
    return result


def _clean_customer_table(df, pd):
    """客户表清洗规则"""
    removed = []
    desc = "客户表清洗完成"

    id_col = None
    for col in df.columns:
        if '身份证' in str(col) or 'id_card' in str(col).lower():
            id_col = col
            break
    if id_col:
        invalid_ids = []
        for idx, val in df[id_col].items():
            if pd.notna(val):
                result = validate_id_card(str(val))
                if not result.get("valid", False):
                    invalid_ids.append({"row": int(idx) + 2, "value": str(val), "error": result.get("error", "")})
        if invalid_ids:
            removed.append({"reason": "身份证校验失败", "count": len(invalid_ids), "samples": invalid_ids[:5]})

    phone_col = None
    for col in df.columns:
        if '手机' in str(col) or '电话' in str(col) or 'phone' in str(col).lower():
            phone_col = col
            break
    if phone_col:
        invalid_phones = []
        for idx, val in df[phone_col].items():
            if pd.notna(val):
                phone = re.sub(r'[^\d]', '', str(val))
                if len(phone) != 11 or not phone.startswith('1'):
                    invalid_phones.append({"row": int(idx) + 2, "value": str(val)})
        if invalid_phones:
            removed.append({"reason": "手机号格式错误", "count": len(invalid_phones), "samples": invalid_phones[:5]})

    card_col = None
    for col in df.columns:
        if '银行卡' in str(col) or '卡号' in str(col) or 'card' in str(col).lower():
            card_col = col
            break
    if card_col:
        invalid_cards = []
        for idx, val in df[card_col].items():
            if pd.notna(val):
                card = re.sub(r'[^\d]', '', str(val))
                if len(card) >= 16:
                    luhn = luhn_check(card)
                    if not luhn.get("valid", False):
                        invalid_cards.append({"row": int(idx) + 2, "value": str(val)})
        if invalid_cards:
            removed.append({"reason": "银行卡Luhn校验失败", "count": len(invalid_cards), "samples": invalid_cards[:5]})

    return df, removed, desc


def _clean_transaction_table(df, pd):
    """交易表清洗规则"""
    removed = []

    amount_col = None
    for col in df.columns:
        if '金额' in str(col) or 'amount' in str(col).lower():
            amount_col = col
            break
    if amount_col:
        invalid_amounts = []
        for idx, val in df[amount_col].items():
            if pd.notna(val):
                try:
                    amount = float(val)
                    df.at[idx, amount_col] = round(amount, 2)
                except (ValueError, TypeError):
                    invalid_amounts.append({"row": int(idx) + 2, "value": str(val)})
        if invalid_amounts:
            removed.append({"reason": "金额格式错误", "count": len(invalid_amounts), "samples": invalid_amounts[:5]})

    date_col = None
    for col in df.columns:
        if '日期' in str(col) or '时间' in str(col) or 'date' in str(col).lower():
            date_col = col
            break
    if date_col:
        invalid_dates = []
        for idx, val in df[date_col].items():
            if pd.notna(val):
                try:
                    pd.to_datetime(str(val))
                except Exception:
                    invalid_dates.append({"row": int(idx) + 2, "value": str(val)})
        if invalid_dates:
            removed.append({"reason": "日期格式错误", "count": len(invalid_dates), "samples": invalid_dates[:5]})

    return df, removed, "交易表清洗完成"


def _clean_account_table(df, pd):
    """账户表清洗规则"""
    removed = []
    desensitized_info = {}

    balance_col = None
    for col in df.columns:
        if '余额' in str(col) or 'balance' in str(col).lower():
            balance_col = col
            break
    if balance_col:
        desensitized_count = 0
        for idx, val in df[balance_col].items():
            if pd.notna(val):
                try:
                    amount = float(val)
                    df.at[idx, balance_col] = desensitize_balance(amount)["desensitized"]
                    desensitized_count += 1
                except (ValueError, TypeError):
                    pass
        desensitized_info["余额脱敏"] = desensitized_count

    email_col = None
    for col in df.columns:
        if '邮箱' in str(col) or 'email' in str(col).lower():
            email_col = col
            break
    if email_col:
        desensitized_count = 0
        for idx, val in df[email_col].items():
            if pd.notna(val) and '@' in str(val):
                df.at[idx, email_col] = desensitize_email(str(val))["masked"]
                desensitized_count += 1
        desensitized_info["邮箱脱敏"] = desensitized_count

    return df, removed, "账户表清洗完成"


def check_referential_integrity(filepath1: str, filepath2: str, col1: str, col2: str) -> dict:
    """检查两个表之间的参照完整性"""
    pd = _get_pd()
    if pd is None:
        return {"success": False, "error": "需要安装pandas"}

    df1, err = _read_data_file(filepath1)
    if df1 is None:
        return {"success": False, "error": f"读取主表失败: {err}"}

    df2, err = _read_data_file(filepath2)
    if df2 is None:
        return {"success": False, "error": f"读取引用表失败: {err}"}

    def find_col(df, col_name):
        for c in df.columns:
            if col_name.lower() in str(c).lower():
                return c
        return None

    actual_col1 = find_col(df1, col1) or col1
    actual_col2 = find_col(df2, col2) or col2

    if actual_col1 not in df1.columns:
        return {"success": False, "error": f"主表中找不到列'{col1}'，可用列: {list(df1.columns)}"}
    if actual_col2 not in df2.columns:
        return {"success": False, "error": f"引用表中找不到列'{col2}'，可用列: {list(df2.columns)}"}

    main_values = set(df1[actual_col1].dropna().astype(str))
    ref_values = set(df2[actual_col2].dropna().astype(str))

    orphaned = main_values - ref_values
    missing_refs = ref_values - main_values

    return {
        "success": True,
        "main_table_rows": len(df1),
        "ref_table_rows": len(df2),
        "main_column": actual_col1,
        "ref_column": actual_col2,
        "orphaned_count": len(orphaned),
        "orphaned_values": sorted(list(orphaned))[:50],
        "unreferenced_count": len(missing_refs),
        "unreferenced_values": sorted(list(missing_refs))[:50],
        "integrity_ok": len(orphaned) == 0
    }


def desensitize_balance(amount: float) -> dict:
    """余额脱敏：保留前2位，中间用*替换，后2位不变"""
    amount_str = f"{amount:.2f}"
    parts = amount_str.split('.')
    integer_part = parts[0]
    decimal_part = parts[1] if len(parts) > 1 else "00"

    if len(integer_part) <= 2:
        masked = integer_part
    elif len(integer_part) <= 4:
        masked = integer_part[:2] + '*' * (len(integer_part) - 2)
    else:
        masked = integer_part[:2] + '*' * (len(integer_part) - 4) + integer_part[-2:]

    formatted = f"{masked}.{decimal_part}"
    return {"original": amount, "desensitized": formatted}


def batch_desensitize_amounts(amounts: list) -> dict:
    """批量金额脱敏"""
    results = []
    for amt in amounts:
        try:
            results.append(desensitize_balance(float(amt)))
        except (ValueError, TypeError):
            results.append({"original": amt, "error": "无效金额"})
    return {"success": True, "count": len(results), "results": results}


def age_to_5year_range(age: int) -> str:
    """年龄转5年区间"""
    start = (age // 5) * 5
    return f"{start}-{start + 4}"


def age_to_decade(age: int) -> str:
    """年龄转10年区间"""
    start = (age // 10) * 10
    return f"{start}-{start + 9}"


def batch_age_transform(ages: list, mode: str = "5year") -> dict:
    """批量年龄转换"""
    transform_fn = age_to_5year_range if mode == "5year" else age_to_decade
    results = []
    distribution = {}
    for age in ages:
        try:
            age_int = int(age)
            range_str = transform_fn(age_int)
            results.append({"age": age_int, "range": range_str})
            distribution[range_str] = distribution.get(range_str, 0) + 1
        except (ValueError, TypeError):
            results.append({"age": age, "error": "无效年龄"})

    return {
        "success": True,
        "mode": mode,
        "count": len(results),
        "results": results,
        "distribution": dict(sorted(distribution.items()))
    }


def auto_desensitize_csv(text: str) -> dict:
    """自动检测并脱敏CSV文本中的敏感信息"""
    lines = text.strip().split('\n')
    if not lines:
        return {"success": False, "error": "空数据"}

    headers = lines[0].split(',')
    result_lines = [lines[0]]
    desensitized_count = {"姓名": 0, "手机号": 0, "身份证": 0, "银行卡": 0, "邮箱": 0}

    for line in lines[1:]:
        fields = line.split(',')
        new_fields = []
        for i, field in enumerate(fields):
            field = field.strip()
            header = headers[i].strip() if i < len(headers) else ""

            if re.match(r'^1[3-9]\d{9}$', field):
                new_fields.append(desensitize_phone(field)["masked"])
                desensitized_count["手机号"] += 1
            elif re.match(r'^\d{17}[\dXx]$', field):
                new_fields.append(desensitize_id_card(field)["masked"])
                desensitized_count["身份证"] += 1
            elif re.match(r'^\d{16,19}$', field):
                new_fields.append(desensitize_bank_card(field)["masked"])
                desensitized_count["银行卡"] += 1
            elif '@' in field and '.' in field.split('@')[-1]:
                new_fields.append(desensitize_email(field)["masked"])
                desensitized_count["邮箱"] += 1
            elif re.match(r'^[一-龥]{2,4}$', field) and header in ("姓名", "name", "名字"):
                new_fields.append(desensitize_name(field))
                desensitized_count["姓名"] += 1
            else:
                new_fields.append(field)

        result_lines.append(','.join(new_fields))

    return {
        "success": True,
        "original_rows": len(lines) - 1,
        "desensitized": desensitized_count,
        "result": '\n'.join(result_lines)
    }
