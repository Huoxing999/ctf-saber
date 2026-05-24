"""CTF工具箱 - Flask后端主程序"""
import os
import json
import traceback
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

from solvers import reverse, crypto, data_sec, archive, stego, traffic, web, firewall
from solvers import log_analysis, forensics, pentest, db_security, server_config, network

app = Flask(__name__, static_folder='templates', static_url_path='')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============ 工具函数 ============

def handle_file_upload(callback):
    """统一处理文件上传：保存 -> 调用callback -> 清理"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    try:
        result = callback(path)
        return jsonify(result)
    finally:
        if os.path.exists(path):
            os.remove(path)


@app.errorhandler(Exception)
def handle_exception(e):
    """全局异常处理，返回JSON而非HTML"""
    tb = traceback.format_exc()
    return jsonify({
        "success": False,
        "error": str(e),
        "type": type(e).__name__
    }), 500


# ============ 页面路由 ============

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')


# ============ 逆向工程 API ============

@app.route('/api/reverse/analyze', methods=['POST'])
def reverse_analyze():
    """分析上传的二进制文件"""
    return handle_file_upload(reverse.analyze_pe)


@app.route('/api/reverse/xor', methods=['POST'])
def reverse_xor():
    """异或爆破"""
    def _process(path):
        with open(path, 'rb') as fp:
            data = fp.read()
        return reverse.xor_bruteforce(data)
    return handle_file_upload(_process)


@app.route('/api/reverse/find-flag', methods=['POST'])
def reverse_find_flag():
    """在文件中搜索flag"""
    def _process(path):
        with open(path, 'rb') as fp:
            data = fp.read()
        strings = reverse.extract_strings(data, min_len=4)
        flags = reverse.find_flags_in_strings(strings)
        return {"flags": flags, "total_strings": len(strings)}
    return handle_file_upload(_process)


# ============ 密码学 API ============

@app.route('/api/crypto/identify', methods=['POST'])
def crypto_identify():
    """自动识别编码类型"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    results = crypto.identify_encoding(text)
    return jsonify({"results": results})


@app.route('/api/crypto/caesar', methods=['POST'])
def crypto_caesar():
    """凯撒密码爆破"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    results = crypto.caesar_bruteforce(text)
    return jsonify({"results": results})


@app.route('/api/crypto/md5', methods=['POST'])
def crypto_md5():
    """MD5反查"""
    data = request.get_json()
    hash_str = data.get('hash', '')
    if not hash_str:
        return jsonify({"success": False, "error": "请输入hash"}), 400
    result = crypto.md5_reverse(hash_str)
    return jsonify(result)


@app.route('/api/crypto/decode', methods=['POST'])
def crypto_decode():
    """多层自动解码"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = crypto.multi_decode(text)
    return jsonify(result)


@app.route('/api/crypto/hash-id', methods=['POST'])
def crypto_hash_id():
    """哈希类型识别"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = crypto.hash_identify(text)
    return jsonify(result)


@app.route('/api/crypto/fence', methods=['POST'])
def crypto_fence():
    """栅栏密码解密"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = crypto.fence_decrypt(text)
    return jsonify(result)


@app.route('/api/crypto/vigenere', methods=['POST'])
def crypto_vigenere():
    """Vigenere密码解密"""
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    if not text or not key:
        return jsonify({"success": False, "error": "请输入文本和密钥"}), 400
    result = crypto.vigenere_decrypt(text, key)
    return jsonify(result)


@app.route('/api/crypto/bacon', methods=['POST'])
def crypto_bacon():
    """培根密码解密"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = crypto.bacon_decrypt(text)
    return jsonify(result)


@app.route('/api/crypto/atbash', methods=['POST'])
def crypto_atbash():
    """Atbash密码解密"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = crypto.atbash_decrypt(text)
    return jsonify(result)


# ============ 数据安全 API ============

@app.route('/api/data/luhn', methods=['POST'])
def data_luhn():
    """Luhn校验"""
    data = request.get_json()
    number = data.get('number', '')
    if not number:
        return jsonify({"success": False, "error": "请输入数字"}), 400
    result = data_sec.luhn_check(number)
    return jsonify(result)


@app.route('/api/data/visa', methods=['POST'])
def data_visa():
    """VISA卡号校验"""
    data = request.get_json()
    number = data.get('number', '')
    if not number:
        return jsonify({"success": False, "error": "请输入卡号"}), 400
    result = data_sec.validate_visa(number)
    return jsonify(result)


@app.route('/api/data/card-type', methods=['POST'])
def data_card_type():
    """银行卡类型识别"""
    data = request.get_json()
    number = data.get('number', '')
    if not number:
        return jsonify({"success": False, "error": "请输入卡号"}), 400
    result = data_sec.identify_card_type(number)
    return jsonify(result)


@app.route('/api/data/id-card', methods=['POST'])
def data_id_card():
    """身份证号校验"""
    data = request.get_json()
    id_number = data.get('id', '')
    if not id_number:
        return jsonify({"success": False, "error": "请输入身份证号"}), 400
    result = data_sec.validate_id_card(id_number)
    return jsonify(result)


@app.route('/api/data/clean', methods=['POST'])
def data_clean():
    """CSV数据清洗"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    rules_json = request.form.get('rules', '{}')
    try:
        rules = json.loads(rules_json)
    except Exception:
        rules = {}
    result = data_sec.clean_csv_data(content, rules)
    return jsonify(result)


@app.route('/api/data/desensitize', methods=['POST'])
def data_desensitize():
    """数据脱敏"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = data_sec.auto_desensitize(text)
    return jsonify(result)


@app.route('/api/data/amount', methods=['POST'])
def data_amount():
    """金额脱敏"""
    data = request.get_json()
    try:
        amount = float(data.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "请输入有效金额"}), 400
    result = data_sec.desensitize_amount(amount)
    return jsonify(result)


@app.route('/api/data/md5', methods=['POST'])
def data_md5():
    """计算MD5"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    return jsonify({"md5": data_sec.compute_md5(text)})


@app.route('/api/data/hash', methods=['POST'])
def data_hash():
    """多算法哈希计算"""
    data = request.get_json()
    text = data.get('text', '')
    algo = data.get('algo', 'md5')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = data_sec.compute_hash(text, algo)
    return jsonify(result)


@app.route('/api/data/file-hash', methods=['POST'])
def data_file_hash():
    """文件哈希校验"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    algo = request.form.get('algo', 'sha256')
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='_' + f.filename) as tmp:
        f.save(tmp.name)
        try:
            result = data_sec.file_hash(tmp.name, algo)
        finally:
            os.unlink(tmp.name)
    return jsonify(result)


@app.route('/api/data/base64', methods=['POST'])
def data_base64():
    """Base64编解码"""
    data = request.get_json()
    text = data.get('text', '')
    mode = data.get('mode', 'encode')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    if mode == 'decode':
        result = data_sec.base64_decode(text)
    else:
        result = data_sec.base64_encode(text)
    return jsonify(result)


@app.route('/api/data/url-encode', methods=['POST'])
def data_url_encode():
    """URL编解码"""
    data = request.get_json()
    text = data.get('text', '')
    mode = data.get('mode', 'encode')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    if mode == 'decode':
        result = data_sec.url_decode(text)
    else:
        result = data_sec.url_encode(text)
    return jsonify(result)


@app.route('/api/data/hex', methods=['POST'])
def data_hex():
    """Hex编解码"""
    data = request.get_json()
    text = data.get('text', '')
    mode = data.get('mode', 'encode')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    if mode == 'decode':
        result = data_sec.hex_decode(text)
    else:
        result = data_sec.hex_encode(text)
    return jsonify(result)


@app.route('/api/data/scan', methods=['POST'])
def data_scan():
    """敏感数据扫描"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = data_sec.scan_sensitive(text)
    return jsonify(result)


@app.route('/api/data/classify', methods=['POST'])
def data_classify():
    """数据分类分级"""
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = data_sec.classify_data(text)
    return jsonify(result)


@app.route('/api/data/password-strength', methods=['POST'])
def data_password_strength():
    """密码强度检测"""
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({"success": False, "error": "请输入密码"}), 400
    result = data_sec.check_password_strength(password)
    return jsonify(result)


@app.route('/api/data/competition-desensitize', methods=['POST'])
def data_competition_desensitize():
    """竞赛一键脱敏"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = data_sec.competition_desensitize(content)
    return jsonify(result)


# ============ 信息网络 API ============

@app.route('/api/network/subnet', methods=['POST'])
def network_subnet():
    """子网计算器"""
    data = request.get_json()
    ip_cidr = data.get('ip_cidr', '')
    if not ip_cidr:
        return jsonify({"success": False, "error": "请输入CIDR格式IP（如192.168.1.0/24）"}), 400
    result = network.subnet_calculator(ip_cidr)
    return jsonify(result)


@app.route('/api/network/subnet-split', methods=['POST'])
def network_subnet_split():
    """子网划分"""
    data = request.get_json()
    ip_cidr = data.get('ip_cidr', '')
    new_prefix = int(data.get('new_prefix', 26))
    if not ip_cidr:
        return jsonify({"success": False, "error": "请输入CIDR格式IP"}), 400
    result = network.subnet_split(ip_cidr, new_prefix)
    return jsonify(result)


@app.route('/api/network/ip-info', methods=['POST'])
def network_ip_info():
    """IP地址信息查询"""
    data = request.get_json()
    ip = data.get('ip', '')
    if not ip:
        return jsonify({"success": False, "error": "请输入IP地址"}), 400
    result = network.ip_info(ip)
    return jsonify(result)


@app.route('/api/network/config', methods=['POST'])
def network_config():
    """网络配置命令"""
    data = request.get_json()
    action = data.get('action', 'show')
    config = data.get('config', {})
    result = network.network_config(action, config)
    return jsonify(result)


@app.route('/api/network/dns', methods=['POST'])
def network_dns():
    """DNS配置"""
    data = request.get_json()
    action = data.get('action', 'install')
    config = data.get('config', {})
    result = network.dns_config(action, config)
    return jsonify(result)


@app.route('/api/network/dhcp', methods=['POST'])
def network_dhcp():
    """DHCP配置"""
    data = request.get_json()
    action = data.get('action', 'install')
    config = data.get('config', {})
    result = network.dhcp_config(action, config)
    return jsonify(result)


@app.route('/api/network/diagnose', methods=['POST'])
def network_diagnose():
    """网络诊断"""
    data = request.get_json()
    action = data.get('action', 'ping')
    config = data.get('config', {})
    result = network.network_diagnose(action, config)
    return jsonify(result)


@app.route('/api/network/service', methods=['POST'])
def network_service():
    """网络服务管理"""
    data = request.get_json()
    action = data.get('action', 'ssh')
    config = data.get('config', {})
    result = network.service_config(action, config)
    return jsonify(result)


@app.route('/api/network/competition', methods=['POST'])
def network_competition():
    """竞赛网络题目"""
    data = request.get_json()
    task_num = int(data.get('task', 1))
    config = data.get('config', {})
    result = network.competition_network_task(task_num, config)
    return jsonify(result)


@app.route('/api/network/scenarios', methods=['GET'])
def network_scenarios():
    """列出网络场景"""
    result = network.list_scenarios()
    return jsonify(result)


# ============ 压缩包 API ============

@app.route('/api/archive/analyze', methods=['POST'])
def archive_analyze():
    """分析压缩包"""
    return handle_file_upload(archive.analyze_zip)


@app.route('/api/archive/bruteforce', methods=['POST'])
def archive_bruteforce():
    """压缩包密码爆破（支持ZIP和RAR）"""
    def _process(path):
        ext = os.path.splitext(path)[1].lower()
        if ext == '.rar':
            return archive.bruteforce_rar(path)
        return archive.bruteforce_zip(path)
    return handle_file_upload(_process)


@app.route('/api/archive/extract', methods=['POST'])
def archive_extract():
    """解压文件（支持ZIP和RAR）"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    password = request.form.get('password', '')
    filename = secure_filename(f.filename)
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)
    try:
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.rar':
            result = archive.extract_rar(path, password=password or None)
        else:
            result = archive.extract_zip(path, password=password or None)
        return jsonify(result)
    finally:
        if os.path.exists(path):
            os.remove(path)


@app.route('/api/archive/fix-encryption', methods=['POST'])
def archive_fix_encryption():
    """修复ZIP伪加密"""
    return handle_file_upload(archive.fix_pseudo_encryption)


# ============ 图片隐写 API ============

@app.route('/api/stego/analyze', methods=['POST'])
def stego_analyze():
    """分析图片"""
    return handle_file_upload(stego.analyze_image)


@app.route('/api/stego/lsb', methods=['POST'])
def stego_lsb():
    """LSB隐写提取"""
    return handle_file_upload(stego.extract_lsb)


@app.route('/api/stego/signature', methods=['POST'])
def stego_signature():
    """文件签名检测"""
    return handle_file_upload(stego.check_file_signature)


@app.route('/api/stego/binwalk', methods=['POST'])
def stego_binwalk():
    """binwalk扫描嵌入文件"""
    return handle_file_upload(stego.binwalk_scan)


@app.route('/api/stego/png-chunks', methods=['POST'])
def stego_png_chunks():
    """PNG分块分析"""
    return handle_file_upload(stego.analyze_png_chunks)


@app.route('/api/stego/gif-frames', methods=['POST'])
def stego_gif_frames():
    """GIF帧分析"""
    return handle_file_upload(stego.analyze_gif_frames)


@app.route('/api/stego/audio', methods=['POST'])
def stego_audio():
    """音频隐写分析"""
    return handle_file_upload(stego.analyze_audio)


# ============ 流量分析 API ============

@app.route('/api/traffic/analyze', methods=['POST'])
def traffic_analyze():
    """分析pcap文件"""
    return handle_file_upload(traffic.analyze_pcap)


@app.route('/api/traffic/strings', methods=['POST'])
def traffic_strings():
    """从pcap提取字符串"""
    return handle_file_upload(traffic.extract_strings_from_pcap)


@app.route('/api/traffic/usb', methods=['POST'])
def traffic_usb():
    """USB键盘流量解析"""
    return handle_file_upload(traffic.parse_usb_keyboard)


# ============ Web安全 API ============

@app.route('/api/web/sqli', methods=['POST'])
def web_sqli():
    """SQL注入payload生成"""
    data = request.get_json()
    db_type = data.get('db_type', 'auto')
    result = web.sqli_payloads(db_type)
    return jsonify(result)


@app.route('/api/web/lfi', methods=['POST'])
def web_lfi():
    """文件包含payload生成"""
    result = web.file_inclusion_payloads()
    return jsonify(result)


@app.route('/api/web/xss', methods=['POST'])
def web_xss():
    """XSS payload生成"""
    result = web.xss_payloads()
    return jsonify(result)


@app.route('/api/web/ssrf', methods=['POST'])
def web_ssrf():
    """SSRF payload生成"""
    result = web.ssrf_payloads()
    return jsonify(result)


@app.route('/api/web/xxe', methods=['POST'])
def web_xxe():
    """XXE payload生成"""
    result = web.xxe_payloads()
    return jsonify(result)


@app.route('/api/web/cmdi', methods=['POST'])
def web_cmdi():
    """命令注入payload生成"""
    result = web.cmd_injection_payloads()
    return jsonify(result)


@app.route('/api/web/sqlmap', methods=['POST'])
def web_sqlmap():
    """生成sqlmap命令"""
    data = request.get_json()
    result = web.generate_sqlmap_cmd(
        url=data.get('url', ''),
        data=data.get('data'),
        cookie=data.get('cookie'),
        method=data.get('method', 'GET')
    )
    return jsonify(result)


# ============ 防火墙 API ============

@app.route('/api/firewall/generate', methods=['POST'])
def firewall_generate():
    """生成防火墙规则"""
    data = request.get_json()
    scenario = data.get('scenario', '')
    config = data.get('config', {})
    platform = data.get('platform', 'iptables')
    if platform == 'nftables':
        result = firewall.generate_nftables_rules(scenario, config)
    elif platform == 'windows':
        result = firewall.generate_windows_rules(scenario, config)
    else:
        result = firewall.generate_iptables_rules(scenario, config)
    return jsonify(result)


@app.route('/api/firewall/analyze', methods=['POST'])
def firewall_analyze():
    """分析防火墙规则"""
    data = request.get_json()
    rules_text = data.get('rules', '')
    if not rules_text:
        return jsonify({"success": False, "error": "请输入规则"}), 400
    result = firewall.analyze_rules(rules_text)
    return jsonify(result)


@app.route('/api/firewall/scenarios', methods=['GET'])
def firewall_scenarios():
    """列出所有防火墙场景"""
    result = firewall.list_scenarios()
    return jsonify(result)


# ============ 日志分析 API ============

@app.route('/api/log/web', methods=['POST'])
def log_web():
    """Web日志分析"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = log_analysis.analyze_web_log(content)
    return jsonify(result)


@app.route('/api/log/auth', methods=['POST'])
def log_auth():
    """系统认证日志分析"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = log_analysis.analyze_auth_log(content)
    return jsonify(result)


@app.route('/api/log/windows', methods=['POST'])
def log_windows():
    """Windows事件日志分析"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = log_analysis.analyze_windows_log(content)
    return jsonify(result)


@app.route('/api/log/json', methods=['POST'])
def log_json():
    """JSON日志分析"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = log_analysis.parse_json_log(content)
    return jsonify(result)


# ============ 电子取证 API ============

@app.route('/api/forensics/metadata', methods=['POST'])
def forensics_metadata():
    """文件元数据分析"""
    return handle_file_upload(forensics.analyze_file_metadata)


@app.route('/api/forensics/recover', methods=['POST'])
def forensics_recover():
    """文件恢复"""
    return handle_file_upload(forensics.recover_deleted_files)


@app.route('/api/forensics/memory', methods=['POST'])
def forensics_memory():
    """内存转储分析"""
    return handle_file_upload(forensics.analyze_memory_dump)


@app.route('/api/forensics/strings', methods=['POST'])
def forensics_strings():
    """字符串提取"""
    return handle_file_upload(forensics.extract_strings_from_dump)


@app.route('/api/forensics/pcap', methods=['POST'])
def forensics_pcap():
    """流量取证"""
    return handle_file_upload(forensics.analyze_pcap_for_forensics)


# ============ 渗透测试 API ============

@app.route('/api/pentest/nmap', methods=['POST'])
def pentest_nmap():
    """生成nmap命令"""
    data = request.get_json()
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'basic')
    result = pentest.generate_nmap_cmd(target, scan_type)
    return jsonify(result)


@app.route('/api/pentest/reverse-shell', methods=['POST'])
def pentest_reverse_shell():
    """生成反弹shell命令"""
    data = request.get_json()
    lhost = data.get('lhost', '')
    lport = int(data.get('lport', 4444))
    shell_type = data.get('shell_type', 'bash')
    result = pentest.generate_reverse_shell_cmd(shell_type, lhost, lport)
    return jsonify(result)


@app.route('/api/pentest/privesc', methods=['POST'])
def pentest_privesc():
    """提权检查命令"""
    data = request.get_json()
    os_type = data.get('os', 'linux')
    result = pentest.check_privilege_escalation(os_type)
    return jsonify(result)


@app.route('/api/pentest/hash-crack', methods=['POST'])
def pentest_hash_crack():
    """hash破解命令生成"""
    data = request.get_json()
    hash_value = data.get('hash', '')
    hash_type = data.get('hash_type', 'auto')
    result = pentest.hash_cracking_commands(hash_value, hash_type)
    return jsonify(result)


@app.route('/api/pentest/msf', methods=['POST'])
def pentest_msf():
    """Metasploit命令生成"""
    data = request.get_json()
    result = pentest.generate_msf_commands(
        exploit=data.get('exploit', ''),
        target=data.get('target', ''),
        port=int(data.get('port', 4444)),
        payload=data.get('payload', '')
    )
    return jsonify(result)


@app.route('/api/pentest/decode-creds', methods=['POST'])
def pentest_decode_creds():
    """解码Base64凭据"""
    data = request.get_json()
    text = data.get('text', '')
    result = pentest.decode_base64_credentials(text)
    return jsonify(result)


@app.route('/api/pentest/info-gather', methods=['POST'])
def pentest_info_gather():
    """信息收集命令集"""
    data = request.get_json()
    target = data.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "请输入目标"}), 400
    result = pentest.information_gathering(target)
    return jsonify(result)


@app.route('/api/pentest/web-enum', methods=['POST'])
def pentest_web_enum():
    """Web枚举命令集"""
    data = request.get_json()
    target = data.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "请输入目标"}), 400
    result = pentest.web_enumeration(target)
    return jsonify(result)


@app.route('/api/pentest/cred-attack', methods=['POST'])
def pentest_cred_attack():
    """凭据攻击命令集"""
    data = request.get_json()
    config = data.get('config', {})
    result = pentest.credential_attacks(config)
    return jsonify(result)


@app.route('/api/pentest/exploit-suggest', methods=['POST'])
def pentest_exploit_suggest():
    """漏洞利用建议"""
    data = request.get_json()
    service = data.get('service', '')
    version = data.get('version', '')
    if not service:
        return jsonify({"success": False, "error": "请输入服务名"}), 400
    result = pentest.exploit_suggestions(service, version)
    return jsonify(result)


@app.route('/api/pentest/post-exploit', methods=['POST'])
def pentest_post_exploit():
    """后渗透命令集"""
    data = request.get_json()
    os_type = data.get('os', 'linux')
    result = pentest.post_exploitation_commands(os_type)
    return jsonify(result)


@app.route('/api/pentest/lateral', methods=['POST'])
def pentest_lateral():
    """横向移动命令集"""
    data = request.get_json()
    os_type = data.get('os', 'linux')
    result = pentest.lateral_movement_commands(os_type)
    return jsonify(result)


@app.route('/api/pentest/competition', methods=['POST'])
def pentest_competition():
    """竞赛渗透题目"""
    data = request.get_json()
    task_num = int(data.get('task', 1))
    config = data.get('config', {})
    result = pentest.competition_pentest_task(task_num, config)
    return jsonify(result)


@app.route('/api/pentest/scenarios', methods=['GET'])
def pentest_scenarios():
    """列出所有渗透场景"""
    result = pentest.list_pentest_scenarios()
    return jsonify(result)


# ============ Web安全 扩展 API ============

@app.route('/api/web/sqli-guide', methods=['POST'])
def web_sqli_guide():
    """SQL注入完整指南"""
    data = request.get_json()
    injection_type = data.get('type', 'all')
    result = web.sqli_complete_guide(injection_type)
    return jsonify(result)


@app.route('/api/web/sqli-bypass', methods=['POST'])
def web_sqli_bypass():
    """SQL注入WAF绕过技巧"""
    result = web.sqli_filter_bypass()
    return jsonify(result)


@app.route('/api/web/db-hardening', methods=['POST'])
def web_db_hardening():
    """数据库安全加固指南"""
    data = request.get_json()
    db_type = data.get('db_type', 'mysql')
    result = web.db_security_hardening(db_type)
    return jsonify(result)


# ============ 数据清洗 API ============

@app.route('/api/clean/luhn', methods=['POST'])
def clean_luhn():
    """Luhn算法校验"""
    data = request.get_json()
    number = data.get('number', '')
    if not number:
        return jsonify({"success": False, "error": "请输入卡号"}), 400
    result = data_sec.luhn_check(number)
    return jsonify(result)


@app.route('/api/clean/id-card', methods=['POST'])
def clean_id_card():
    """身份证校验"""
    data = request.get_json()
    id_number = data.get('id', '')
    if not id_number:
        return jsonify({"success": False, "error": "请输入身份证号"}), 400
    result = data_sec.validate_id_card(id_number)
    return jsonify(result)


@app.route('/api/clean/desensitize', methods=['POST'])
def clean_desensitize():
    """CSV自动脱敏"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = data_sec.auto_desensitize_csv(content)
    return jsonify(result)


@app.route('/api/clean/hash', methods=['POST'])
def clean_hash():
    """计算哈希值"""
    data = request.get_json()
    text = data.get('text', '')
    algo = data.get('algo', 'md5')
    if not text:
        return jsonify({"success": False, "error": "请输入文本"}), 400
    result = data_sec.compute_hash(text, algo)
    return jsonify(result)


@app.route('/api/clean/preview', methods=['POST'])
def clean_preview():
    """数据清洗预览"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    content = f.read().decode('utf-8', errors='ignore')
    result = data_sec.clean_data_preview(content)
    return jsonify(result)


# ============ 数据库安全 API ============

@app.route('/api/db/create-table', methods=['POST'])
def db_create_table():
    """生成CREATE TABLE语句"""
    data = request.get_json()
    table_name = data.get('table_name', '')
    columns = data.get('columns', [])
    result = db_security.generate_create_table(table_name, columns)
    return jsonify(result)


@app.route('/api/db/generate-sql', methods=['POST'])
def db_generate_sql():
    """生成SQL语句"""
    data = request.get_json()
    sql_type = data.get('type', 'select')
    table = data.get('table', '')

    if sql_type == 'insert':
        result = db_security.generate_insert(table, data.get('data', {}))
    elif sql_type == 'update':
        result = db_security.generate_update(table, data.get('data', {}), data.get('where', ''))
    elif sql_type == 'select':
        result = db_security.generate_select(table, data.get('columns', '*'), data.get('where', ''), data.get('order_by', ''), data.get('limit', 0))
    else:
        result = {"success": False, "error": f"未知类型: {sql_type}"}
    return jsonify(result)


@app.route('/api/db/security-check', methods=['POST'])
def db_security_check():
    """数据库安全加固检查"""
    data = request.get_json()
    db_type = data.get('db_type', 'mysql')
    if db_type == 'redis':
        result = db_security.redis_security_checklist()
    else:
        result = db_security.mysql_security_checklist()
    return jsonify(result)


@app.route('/api/db/student-db', methods=['POST'])
def db_student_db():
    """生成学生管理数据库"""
    result = db_security.generate_student_management_db()
    return jsonify(result)


@app.route('/api/db/syntax', methods=['POST'])
def db_syntax():
    """SQL语法速查"""
    result = db_security.sql_syntax_reference()
    return jsonify(result)


@app.route('/api/db/competition-templates', methods=['POST'])
def db_competition_templates():
    """竞赛SQL题模板库"""
    result = db_security.competition_sql_templates()
    return jsonify(result)


@app.route('/api/db/validate-sql', methods=['POST'])
def db_validate_sql():
    """SQL语句自动纠错"""
    data = request.get_json()
    sql_text = data.get('sql', '')
    if not sql_text:
        return jsonify({"success": False, "error": "请输入SQL语句"}), 400
    result = db_security.sql_validate(sql_text)
    return jsonify(result)


@app.route('/api/db/join', methods=['POST'])
def db_join():
    """JOIN查询生成"""
    data = request.get_json()
    tables = data.get('tables', [])
    join_type = data.get('join_type', 'INNER')
    group_by = data.get('group_by', '')
    having = data.get('having', '')
    count_col = data.get('count_col', '')
    if not tables:
        return jsonify({"success": False, "error": "请指定表名"}), 400
    # Convert simple string table names to expected dict format
    formatted = []
    for i, t in enumerate(tables):
        if isinstance(t, str):
            entry = {"name": t, "columns": "*"}
            if i > 0:
                prev = tables[0] if isinstance(tables[0], str) else tables[0].get('name', 't0')
                entry["on"] = f"{t}.id = {prev}.id"
            formatted.append(entry)
        else:
            formatted.append(t)
    result = db_security.generate_join_query(formatted, join_type, group_by, having, count_col)
    return jsonify(result)


@app.route('/api/db/design-template', methods=['POST'])
def db_design_template():
    """竞赛数据库设计题模板"""
    data = request.get_json()
    scenario = data.get('scenario', 'student')
    result = db_security.competition_db_design(scenario)
    return jsonify(result)


@app.route('/api/db/competition', methods=['POST'])
def db_competition():
    """竞赛数据库题目一键生成"""
    data = request.get_json()
    task_num = int(data.get('task', 1))
    config = data.get('config', {})
    result = db_security.competition_db_task(task_num, config)
    return jsonify(result)


@app.route('/api/db/scenarios', methods=['GET'])
def db_scenarios():
    """列出所有数据库场景"""
    result = db_security.list_db_scenarios()
    return jsonify(result)


# ============ 数据清洗扩展 API ============

@app.route('/api/clean/excel', methods=['POST'])
def clean_excel():
    """Excel文件解析"""
    return handle_file_upload(data_sec.parse_excel)


@app.route('/api/clean/excel-to-csv', methods=['POST'])
def clean_excel_to_csv():
    """Excel转CSV"""
    def _process(path):
        sheet_name = request.form.get('sheet', None)
        return data_sec.excel_to_csv(path, sheet_name)
    return handle_file_upload(_process)


@app.route('/api/clean/competition', methods=['POST'])
def clean_competition():
    """一键竞赛清洗"""
    def _process(path):
        table_type = request.form.get('table_type', 'customer')
        return data_sec.competition_clean(path, table_type)
    return handle_file_upload(_process)


@app.route('/api/clean/ref-integrity', methods=['POST'])
def clean_ref_integrity():
    """跨表参照完整性校验"""
    files = request.files.getlist('files')
    if len(files) < 2:
        return jsonify({"success": False, "error": "需要上传两个文件（主表和引用表）"}), 400

    col1 = request.form.get('col1', '')
    col2 = request.form.get('col2', '')

    path1 = os.path.join(UPLOAD_DIR, secure_filename(files[0].filename))
    path2 = os.path.join(UPLOAD_DIR, secure_filename(files[1].filename))
    files[0].save(path1)
    files[1].save(path2)
    try:
        result = data_sec.check_referential_integrity(path1, path2, col1, col2)
        return jsonify(result)
    finally:
        for p in (path1, path2):
            if os.path.exists(p):
                os.remove(p)


@app.route('/api/clean/balance', methods=['POST'])
def clean_balance():
    """余额脱敏"""
    data = request.get_json()
    amounts = data.get('amounts', [])
    if not amounts:
        return jsonify({"success": False, "error": "请输入金额列表"}), 400
    result = data_sec.batch_desensitize_amounts(amounts)
    return jsonify(result)


@app.route('/api/clean/age-transform', methods=['POST'])
def clean_age_transform():
    """批量年龄转换"""
    data = request.get_json()
    ages = data.get('ages', [])
    mode = data.get('mode', '5year')
    if not ages:
        return jsonify({"success": False, "error": "请输入年龄列表"}), 400
    result = data_sec.batch_age_transform(ages, mode)
    return jsonify(result)


# ============ 防火墙竞赛题 API ============

@app.route('/api/firewall/competition', methods=['POST'])
def firewall_competition():
    """竞赛防火墙题目"""
    data = request.get_json()
    task_num = int(data.get('task', 1))
    config = data.get('config', {})
    result = firewall.competition_firewall_task(task_num, config)
    return jsonify(result)


# ============ 服务器配置 API ============

@app.route('/api/server/user', methods=['POST'])
def server_user():
    """用户管理命令生成"""
    data = request.get_json()
    action = data.get('action', 'create')
    config = data.get('config', {})
    result = server_config.user_management(action, config)
    return jsonify(result)


@app.route('/api/server/ssh', methods=['POST'])
def server_ssh():
    """SSH安全加固配置"""
    data = request.get_json()
    config = data.get('config', {})
    result = server_config.ssh_hardening(config)
    return jsonify(result)


@app.route('/api/server/service', methods=['POST'])
def server_service():
    """服务管理命令"""
    data = request.get_json()
    action = data.get('action', 'status')
    config = data.get('config', {})
    result = server_config.service_management(action, config)
    return jsonify(result)


@app.route('/api/server/permissions', methods=['POST'])
def server_permissions():
    """文件权限管理命令"""
    data = request.get_json()
    action = data.get('action', 'chmod')
    config = data.get('config', {})
    result = server_config.file_permissions(action, config)
    return jsonify(result)


@app.route('/api/server/network', methods=['POST'])
def server_network():
    """网络配置命令"""
    data = request.get_json()
    action = data.get('action', 'show')
    config = data.get('config', {})
    result = server_config.network_config(action, config)
    return jsonify(result)


@app.route('/api/server/log', methods=['POST'])
def server_log():
    """日志审计配置"""
    data = request.get_json()
    action = data.get('action', 'system-log')
    config = data.get('config', {})
    result = server_config.log_audit(action, config)
    return jsonify(result)


@app.route('/api/server/hardening', methods=['POST'])
def server_hardening():
    """系统安全加固"""
    data = request.get_json()
    action = data.get('action', 'selinux')
    config = data.get('config', {})
    result = server_config.system_hardening(action, config)
    return jsonify(result)


@app.route('/api/server/competition', methods=['POST'])
def server_competition():
    """竞赛服务器配置题目"""
    data = request.get_json()
    task_num = int(data.get('task', 1))
    config = data.get('config', {})
    result = server_config.competition_server_task(task_num, config)
    return jsonify(result)


@app.route('/api/server/scenarios', methods=['GET'])
def server_scenarios():
    """列出所有服务器配置场景"""
    result = server_config.list_server_scenarios()
    return jsonify(result)


# ============ 取证扩展 API ============

@app.route('/api/forensics/volatility', methods=['POST'])
def forensics_volatility():
    """Volatility内存取证命令"""
    data = request.get_json()
    dump_type = data.get('type', 'all')
    result = forensics.volatility_commands(dump_type)
    return jsonify(result)


@app.route('/api/forensics/disk', methods=['POST'])
def forensics_disk():
    """磁盘取证命令"""
    result = forensics.disk_forensics_commands()
    return jsonify(result)


@app.route('/api/forensics/evidence-guide', methods=['POST'])
def forensics_evidence_guide():
    """电子证据收集指南"""
    result = forensics.evidence_collection_guide()
    return jsonify(result)


@app.route('/api/forensics/hex-dump', methods=['POST'])
def forensics_hex_dump():
    """十六进制转储分析"""
    f = request.files.get('file')
    if not f:
        return jsonify({"success": False, "error": "未上传文件"}), 400
    offset = int(request.form.get('offset', 0))
    length = int(request.form.get('length', 512))
    path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    try:
        result = forensics.hex_dump(path, offset, length)
        return jsonify(result)
    finally:
        if os.path.exists(path):
            os.remove(path)


@app.route('/api/forensics/file-signature', methods=['POST'])
def forensics_file_signature():
    """文件签名扫描"""
    return handle_file_upload(forensics.file_signature_scan)


@app.route('/api/forensics/exif', methods=['POST'])
def forensics_exif():
    """EXIF元数据分析"""
    return handle_file_upload(forensics.exif_analysis)


@app.route('/api/forensics/sqlite', methods=['POST'])
def forensics_sqlite():
    """SQLite数据库取证"""
    return handle_file_upload(forensics.sqlite_analysis)


@app.route('/api/forensics/timeline', methods=['POST'])
def forensics_timeline():
    """时间线分析"""
    return handle_file_upload(forensics.timeline_analysis)


@app.route('/api/forensics/registry', methods=['POST'])
def forensics_registry():
    """注册表分析"""
    return handle_file_upload(forensics.registry_analysis)


@app.route('/api/forensics/stego-detect', methods=['POST'])
def forensics_stego_detect():
    """隐写检测"""
    return handle_file_upload(forensics.stego_detect)


@app.route('/api/forensics/network-cmds', methods=['POST'])
def forensics_network_cmds():
    """网络取证命令"""
    result = forensics.network_forensics_commands()
    return jsonify(result)


@app.route('/api/forensics/mobile-cmds', methods=['POST'])
def forensics_mobile_cmds():
    """移动设备取证命令"""
    result = forensics.mobile_forensics_commands()
    return jsonify(result)


@app.route('/api/forensics/competition', methods=['POST'])
def forensics_competition():
    """竞赛取证题目"""
    data = request.get_json()
    task_num = int(data.get('task', 1))
    config = data.get('config', {})
    result = forensics.competition_forensics_task(task_num, config)
    return jsonify(result)


@app.route('/api/forensics/scenarios', methods=['GET'])
def forensics_scenarios():
    """列出所有取证场景"""
    result = forensics.list_forensics_scenarios()
    return jsonify(result)


# ============ 自动检测 API ============

@app.route('/api/auto', methods=['POST'])
def auto_detect():
    """自动检测输入类型并调用对应的解题器"""
    f = request.files.get('file')
    text = request.form.get('text', '')

    results = {"detected_type": None, "results": []}

    if f:
        filename = secure_filename(f.filename)
        path = os.path.join(UPLOAD_DIR, filename)
        f.save(path)

        try:
            ext = os.path.splitext(filename)[1].lower()

            if ext in ('.exe', '.dll', '.sys', '.elf', '.bin', '.so'):
                results["detected_type"] = "可执行文件/逆向分析"
                pe_result = reverse.analyze_pe(path)
                results["results"].append({"module": "PE分析", "data": pe_result})

                with open(path, 'rb') as fp:
                    data = fp.read()
                xor_result = reverse.xor_bruteforce(data)
                if xor_result["flags"]:
                    results["results"].append({"module": "异或爆破", "data": xor_result})

            elif ext in ('.zip',):
                results["detected_type"] = "压缩包"
                zip_result = archive.analyze_zip(path)
                results["results"].append({"module": "ZIP分析", "data": zip_result})
                if zip_result.get("needs_password"):
                    bf_result = archive.bruteforce_zip(path)
                    results["results"].append({"module": "密码爆破", "data": bf_result})

            elif ext in ('.rar',):
                results["detected_type"] = "RAR压缩包"
                rar_result = archive.analyze_rar(path)
                results["results"].append({"module": "RAR分析", "data": rar_result})
                if rar_result.get("needs_password"):
                    bf_result = archive.bruteforce_rar(path)
                    results["results"].append({"module": "RAR密码爆破", "data": bf_result})

            elif ext in ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico'):
                results["detected_type"] = "图片/隐写分析"
                img_result = stego.analyze_image(path)
                results["results"].append({"module": "图片分析", "data": img_result})
                lsb_result = stego.extract_lsb(path)
                if lsb_result.get("success") and lsb_result.get("flags"):
                    results["results"].append({"module": "LSB隐写", "data": lsb_result})
                sig_result = stego.check_file_signature(path)
                results["results"].append({"module": "文件签名", "data": sig_result})

            elif ext in ('.pcap', '.pcapng', '.cap'):
                results["detected_type"] = "流量包分析"
                pcap_result = traffic.analyze_pcap(path)
                results["results"].append({"module": "流量分析", "data": pcap_result})

            elif ext in ('.wav', '.mp3'):
                results["detected_type"] = "音频文件"
                audio_result = stego.analyze_audio(path)
                results["results"].append({"module": "音频分析", "data": audio_result})

            elif ext in ('.csv',):
                results["detected_type"] = "CSV数据文件"
                with open(path, 'r', errors='ignore') as fp:
                    content = fp.read()
                clean_result = data_sec.auto_desensitize_csv(content)
                results["results"].append({"module": "数据脱敏", "data": clean_result})
                preview_result = data_sec.clean_data_preview(content)
                results["results"].append({"module": "数据质量", "data": preview_result})

            elif ext in ('.log', '.txt'):
                results["detected_type"] = "日志文件"
                with open(path, 'r', errors='ignore') as fp:
                    content = fp.read()
                if any(kw in content.lower() for kw in ['get ', 'post ', 'http/', '404', '200', 'user-agent']):
                    log_result = log_analysis.analyze_web_log(content)
                    results["results"].append({"module": "Web日志分析", "data": log_result})
                elif 'sshd' in content or 'login' in content.lower():
                    log_result = log_analysis.analyze_auth_log(content)
                    results["results"].append({"module": "认证日志分析", "data": log_result})
                else:
                    strings = reverse.extract_strings(content.encode('utf-8', errors='ignore'))
                    flags = reverse.find_flags_in_strings(strings)
                    results["results"].append({"module": "字符串提取", "data": {"flags": flags}})

            elif ext in ('.raw', '.dmp', '.mem', '.vmem'):
                results["detected_type"] = "内存转储"
                mem_result = forensics.analyze_memory_dump(path)
                results["results"].append({"module": "内存分析", "data": mem_result})
                vol_cmds = forensics.volatility_commands('all')
                results["results"].append({"module": "Volatility命令", "data": vol_cmds})

            elif ext in ('.dd', '.img', '.E01', '.001'):
                results["detected_type"] = "磁盘镜像"
                meta_result = forensics.analyze_file_metadata(path)
                results["results"].append({"module": "文件元数据", "data": meta_result})
                recover_result = forensics.recover_deleted_files(path)
                results["results"].append({"module": "文件恢复", "data": recover_result})
                disk_cmds = forensics.disk_forensics_commands()
                results["results"].append({"module": "磁盘取证命令", "data": disk_cmds})

            elif ext in ('.xlsx', '.xls'):
                results["detected_type"] = "Excel数据文件"
                excel_result = data_sec.parse_excel(path)
                results["results"].append({"module": "Excel解析", "data": excel_result})
                quality_result = data_sec.analyze_excel_quality(path)
                results["results"].append({"module": "数据质量", "data": quality_result})

            elif ext in ('.sql',):
                results["detected_type"] = "SQL文件"
                with open(path, 'r', errors='ignore') as fp:
                    content = fp.read()
                validate_result = db_security.sql_validate(content)
                results["results"].append({"module": "SQL检查", "data": validate_result})

            else:
                results["detected_type"] = "通用文件分析"
                with open(path, 'rb') as fp:
                    data = fp.read()
                strings = reverse.extract_strings(data)
                flags = reverse.find_flags_in_strings(strings)
                results["results"].append({
                    "module": "字符串提取",
                    "data": {"flags": flags, "total_strings": len(strings)}
                })
        finally:
            if os.path.exists(path):
                os.remove(path)

    elif text:
        text = text.strip()
        results["detected_type"] = "文本/编码分析"

        encodings = crypto.identify_encoding(text)
        if encodings:
            results["results"].append({"module": "编码识别", "data": encodings})

        if len(text) in (32, 40, 56, 64, 96, 128):
            hash_result = crypto.hash_identify(text)
            results["results"].append({"module": "哈希识别", "data": hash_result})

            if len(text) == 32:
                md5_result = crypto.md5_reverse(text)
                results["results"].append({"module": "MD5反查", "data": md5_result})

        decode_result = crypto.multi_decode(text)
        if decode_result["layers"] and decode_result["layers"][0]["method"] != "None":
            results["results"].append({"module": "多层解码", "data": decode_result})

        flags = reverse.find_flags_in_text(text)
        if flags:
            results["results"].append({"module": "Flag提取", "data": {"flags": flags}})

        if text.isalpha() and len(text) >= 5:
            caesar_result = crypto.caesar_bruteforce(text)
            results["results"].append({"module": "凯撒爆破", "data": caesar_result[:5]})

        desensitize_result = data_sec.auto_desensitize(text)
        if desensitize_result["found"] > 0:
            results["results"].append({"module": "敏感数据检测", "data": desensitize_result})

        # 银行卡号检测(Luhn校验)
        import re
        card_match = re.search(r'\b\d{16,19}\b', text)
        if card_match:
            luhn_result = data_sec.luhn_check(card_match.group())
            if luhn_result.get("success"):
                results["results"].append({"module": "银行卡校验", "data": luhn_result})

        # 身份证号检测
        id_match = re.search(r'\b\d{17}[\dXx]\b', text)
        if id_match:
            id_result = data_sec.validate_id_card(id_match.group())
            if id_result.get("success"):
                results["results"].append({"module": "身份证校验", "data": id_result})

        # SQL注入特征检测
        sqli_keywords = ['union select', 'order by', 'extractvalue', 'updatexml', 'sleep(', 'benchmark(', 'information_schema', 'group_concat']
        if any(kw in text.lower() for kw in sqli_keywords):
            results["results"].append({"module": "SQL注入检测", "data": {"提示": "检测到SQL注入特征", "建议": "使用Web安全Tab的SQL注入指南"}})

        # iptables规则检测
        if 'iptables' in text:
            results["results"].append({"module": "防火墙规则", "data": {"提示": "检测到iptables规则", "建议": "使用防火墙Tab进行规则生成和验证"}})

        # Base64凭据检测
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', text):
            cred_result = pentest.decode_base64_credentials(text)
            if cred_result.get("success"):
                results["results"].append({"module": "Base64解码", "data": cred_result})

    else:
        return jsonify({"success": False, "error": "请上传文件或输入文本"}), 400

    return jsonify(results)


if __name__ == '__main__':
    print("=" * 50)
    print("  CTF工具箱")
    print("  打开浏览器访问: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(host='127.0.0.1', port=5000, debug=False)
