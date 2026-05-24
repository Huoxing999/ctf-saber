"""数据清洗与脱敏模块 - 数据治理、Luhn校验、PII脱敏、Excel处理、竞赛清洗"""
import re
import os
import hashlib
import datetime
from solvers.common import find_flags_in_text

# pandas 延迟导入
def _get_pd():
    try:
        import pandas as pd
        return pd
    except ImportError:
        return None


def luhn_check(card_number: str) -> dict:
    """Luhn算法校验银行卡号"""
    card = card_number.replace(" ", "").replace("-", "")

    if not card.isdigit():
        return {"success": False, "error": "卡号包含非数字字符"}

    digits = [int(d) for d in card]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d

    valid = checksum % 10 == 0

    # 卡种识别
    card_type = "未知"
    if card.startswith("4"):
        card_type = "VISA"
    elif card.startswith("5") and len(card) >= 2 and 51 <= int(card[:2]) <= 55:
        card_type = "MasterCard"
    elif card.startswith("3") and len(card) >= 2 and card[:2] in ("34", "37"):
        card_type = "American Express"
    elif card.startswith("6"):
        card_type = "UnionPay"
    elif card.startswith("3") and len(card) >= 3 and 3528 <= int(card[:4]) <= 3589:
        card_type = "JCB"

    return {
        "success": True,
        "card_number": card,
        "card_type": card_type,
        "length": len(card),
        "luhn_valid": valid,
        "checksum": checksum % 10
    }


def validate_id_card(id_number: str) -> dict:
    """校验中国大陆身份证号(18位)"""
    id_num = id_number.strip()

    if len(id_num) != 18:
        return {"success": True, "valid": False, "error": f"长度错误: {len(id_num)}位(应为18位)"}

    if not re.match(r'^\d{17}[\dXx]$', id_num):
        return {"success": True, "valid": False, "error": "格式错误"}

    # 加权因子
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = "10X98765432"

    total = sum(int(id_num[i]) * weights[i] for i in range(17))
    expected = check_codes[total % 11]

    if id_num[17].upper() != expected:
        return {"success": True, "valid": False, "error": f"校验码错误(应为{expected})"}

    # 提取信息
    birth = id_num[6:14]
    year = int(birth[:4])
    month = int(birth[4:6])
    day = int(birth[6:8])

    import datetime
    now = datetime.datetime.now()
    age = now.year - year

    gender = "男" if int(id_num[16]) % 2 == 1 else "女"

    return {
        "success": True,
        "valid": True,
        "id_number": id_num,
        "birth": f"{year}-{month:02d}-{day:02d}",
        "age": age,
        "gender": gender,
        "region_code": id_num[:6]
    }


def desensitize_name(name: str) -> str:
    """姓名脱敏: 保留姓，其余用*"""
    if not name or len(name) < 2:
        return name
    return name[0] + "*" * (len(name) - 1)


def desensitize_phone(phone: str) -> str:
    """手机号脱敏: 前3后4"""
    p = re.sub(r'[^\d]', '', phone)
    if len(p) == 11:
        return p[:3] + "****" + p[-4:]
    return phone


def desensitize_id_card(id_num: str) -> str:
    """身份证脱敏: 前3后4"""
    if len(id_num) >= 14:
        return id_num[:3] + "***********" + id_num[-4:]
    return id_num


def desensitize_bank_card(card: str) -> str:
    """银行卡脱敏: 前6后4"""
    c = re.sub(r'[^\d]', '', card)
    if len(c) >= 10:
        return c[:6] + "****" + c[-4:]
    return card


def desensitize_email(email: str) -> str:
    """邮箱脱敏: 首字符***@域名"""
    if '@' in email:
        local, domain = email.split('@', 1)
        if len(local) > 1:
            return local[0] + "***@" + domain
    return email


def age_to_range(age: int) -> str:
    """年龄转5年区间"""
    start = (age // 5) * 5
    return f"{start}-{start + 4}"


def auto_desensitize_csv(text: str) -> dict:
    """自动检测并脱敏CSV文本中的敏感信息"""
    lines = text.strip().split('\n')
    if not lines:
        return {"success": False, "error": "空数据"}

    headers = lines[0].split(',')
    result_lines = [lines[0]]  # 保留表头
    desensitized_count = {field: 0 for field in ["姓名", "手机号", "身份证", "银行卡", "邮箱"]}

    for line in lines[1:]:
        fields = line.split(',')
        new_fields = []
        for i, field in enumerate(fields):
            field = field.strip()
            header = headers[i].strip() if i < len(headers) else ""

            # 手机号
            if re.match(r'^1[3-9]\d{9}$', field):
                new_fields.append(desensitize_phone(field))
                desensitized_count["手机号"] += 1
            # 身份证
            elif re.match(r'^\d{17}[\dXx]$', field):
                new_fields.append(desensitize_id_card(field))
                desensitized_count["身份证"] += 1
            # 银行卡
            elif re.match(r'^\d{16,19}$', field):
                new_fields.append(desensitize_bank_card(field))
                desensitized_count["银行卡"] += 1
            # 邮箱
            elif '@' in field and '.' in field.split('@')[-1]:
                new_fields.append(desensitize_email(field))
                desensitized_count["邮箱"] += 1
            # 姓名(2-4个汉字)
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


def generate_hash(text: str, algo: str = "md5") -> dict:
    """计算文本哈希值"""
    data = text.encode('utf-8')
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    if algo not in algos:
        return {"success": False, "error": f"不支持的算法: {algo}", "available": list(algos.keys())}

    h = algos[algo](data).hexdigest()
    return {"success": True, "text": text, "algorithm": algo, "hash": h}


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

        # 空值检测
        if any(f.strip() == '' or f.strip().lower() == 'null' for f in fields):
            issues["null_rows"] += 1

        # 空白字符问题
        if any(f != f.strip() for f in fields):
            issues["whitespace_issues"] += 1

        # 重复行
        if line in seen_rows:
            issues["duplicate_rows"] += 1
        seen_rows.add(line)

        # 只记录前5个问题示例
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


# ============ Excel 文件处理 ============

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
                # 检查混合类型
                non_null = df[col].dropna()
                if len(non_null) > 0:
                    types = non_null.apply(type).nunique()
                    if types > 1:
                        issues["type_issues"].append(f"列'{col}'包含混合数据类型")
            all_issues[sheet_name] = issues
        return {"success": True, "sheets": all_issues}
    except Exception as e:
        return {"success": False, "error": f"分析失败: {str(e)}"}


# ============ 一键竞赛清洗 ============

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
        # 客户表清洗
        df, removed, desc = _clean_customer_table(df, pd)
        removed_rows.extend(removed)
        desensitized["table_type"] = "客户表"
    elif table_type == "transaction":
        # 交易表清洗
        df, removed, desc = _clean_transaction_table(df, pd)
        removed_rows.extend(removed)
        desensitized["table_type"] = "交易表"
    elif table_type == "account":
        # 账户表清洗
        df, removed, desc = _clean_account_table(df, pd)
        removed_rows.extend(removed)
        desensitized["table_type"] = "账户表"
    else:
        return {"success": False, "error": f"不支持的表类型: {table_type}，可选: customer, transaction, account"}

    # 通用清洗：去空行、去重
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

    # 生成清洗后的CSV
    result["cleaned_csv"] = df.to_csv(index=False)
    return result


def _clean_customer_table(df, pd):
    """客户表清洗规则"""
    removed = []
    desc = "客户表清洗完成"

    # 身份证校验
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

    # 手机号校验
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

    # 银行卡Luhn校验
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
                    if not luhn.get("luhn_valid", False):
                        invalid_cards.append({"row": int(idx) + 2, "value": str(val)})
        if invalid_cards:
            removed.append({"reason": "银行卡Luhn校验失败", "count": len(invalid_cards), "samples": invalid_cards[:5]})

    return df, removed, desc


def _clean_transaction_table(df, pd):
    """交易表清洗规则"""
    removed = []

    # 金额格式化
    amount_col = None
    for col in df.columns:
        if '金额' in str(col) or 'amount' in str(col).lower() or '金额' in str(col):
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

    # 日期标准化
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

    # 余额脱敏
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

    # 邮箱脱敏
    email_col = None
    for col in df.columns:
        if '邮箱' in str(col) or 'email' in str(col).lower():
            email_col = col
            break
    if email_col:
        desensitized_count = 0
        for idx, val in df[email_col].items():
            if pd.notna(val) and '@' in str(val):
                df.at[idx, email_col] = desensitize_email(str(val))
                desensitized_count += 1
        desensitized_info["邮箱脱敏"] = desensitized_count

    return df, removed, "账户表清洗完成"


# ============ 跨表参照完整性校验 ============

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

    # 查找匹配的列名
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


# ============ 余额脱敏 ============

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
    return {
        "original": amount,
        "formatted": formatted
    }


def batch_desensitize_amounts(amounts: list) -> dict:
    """批量金额脱敏"""
    results = []
    for amt in amounts:
        try:
            results.append(desensitize_balance(float(amt)))
        except (ValueError, TypeError):
            results.append({"original": amt, "error": "无效金额"})
    return {"success": True, "count": len(results), "results": results}


# ============ 年龄分段 ============

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
