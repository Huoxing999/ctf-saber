# CTF工具箱 - 设计与实现文档

> 项目路径: C:\Users\HeHesama\Desktop\2605网安培训班\ctf_practice\
> 最后更新: 2026-05-21

---

## 一、项目概述

### 1.1 项目目标
结合2605网安培训班的所有练习内容（CTF逆向、密码学、数据安全、防火墙配置、Web安全等），
开发一套**离线版**的CTF工具箱，通过浏览器访问即可使用。

### 1.2 技术栈
- 后端: Python + Flask（本地Web服务器）
- 前端: 单文件HTML + 原生CSS + JavaScript（无框架依赖）
- 解题模块: 纯Python实现，仅依赖常见库

### 1.3 运行方式
```bash
cd C:\Users\HeHesama\Desktop\2605网安培训班\ctf_practice
pip install flask pillow pefile  # 首次运行需要安装依赖
python app.py
# 浏览器打开 http://127.0.0.1:5000
```

---

## 二、项目结构

```
ctf_practice/
├── app.py                    # Flask后端主程序 (485行) ✅ 完成
├── README.md                 # 项目说明 ✅ 完成
├── DESIGN.md                 # 本文档 ✅ 完成
├── uploads/                  # 临时上传目录 (自动创建)
├── solvers/                  # 解题模块目录
│   ├── __init__.py           # 包初始化 ✅ 完成
│   ├── reverse.py            # 逆向工程模块 (171行) ✅ 完成
│   ├── crypto.py             # 密码学模块 (244行) ✅ 完成
│   ├── data_sec.py           # 数据安全模块 (241行) ✅ 完成
│   ├── archive.py            # 压缩包模块 (132行) ✅ 完成
│   ├── stego.py              # 图片隐写模块 (139行) ✅ 完成
│   ├── traffic.py            # 流量分析模块 (140行) ✅ 完成
│   ├── firewall.py           # 防火墙模块 (178行) ✅ 完成
│   └── web.py                # Web安全模块 (约200行) ✅ 刚完成
└── templates/
    └── index.html            # 前端页面 ❌ 待开发
```

---

## 三、各模块功能详解

### 3.1 逆向工程模块 (reverse.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| PE文件分析 | POST /api/reverse/analyze | 分析EXE/DLL的区段、资源段、导入表、提取字符串和flag |
| 异或爆破 | POST /api/reverse/xor | 单字节/双字节异或爆破，自动评分 |
| Flag搜索 | POST /api/reverse/find-flag | 在文件中搜索 flag{}、ctf{}、key{} 格式字符串 |

核心能力:
- 自动提取PE文件的区段信息（名称、大小、熵值）
- 扫描资源段中的隐藏字符串（来自"刮开有奖"题目的经验）
- 导入表分析（查看调用了哪些API）
- 异或爆破+英文频率评分
- 支持无pefile库时的降级处理（纯二进制读取）

### 3.2 密码学模块 (crypto.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| 编码识别 | POST /api/crypto/identify | 自动识别Base64/Base32/Hex/URL/Unicode/Binary编码 |
| 凯撒爆破 | POST /api/crypto/caesar | 26种位移全部尝试 |
| MD5反查 | POST /api/crypto/md5 | 内置字典 + 暴力枚举10万数字 + 常见密码 |
| 多层解码 | POST /api/crypto/decode | 最多5层自动解码（Base64→Hex→URL混合） |
| 哈希识别 | POST /api/crypto/hash-id | 识别MD5/SHA1/SHA256/bcrypt等哈希类型 |

核心能力:
- 内置30+常见MD5字典
- 支持Base64/Base32/Hex/Binary/URL/Unicode等多种编码自动识别
- 多层编码自动剥离（CTF常见的编码套编码场景）
- 编码识别带置信度评分

### 3.3 数据安全模块 (data_sec.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| Luhn校验 | POST /api/data/luhn | 信用卡号Luhn算法验证 |
| VISA校验 | POST /api/data/visa | VISA卡号格式+Luhn双重校验 |
| 身份证校验 | POST /api/data/id-card | 18位身份证号全维度校验（地区码+生日+校验码） |
| CSV清洗 | POST /api/data/clean | 按规则清洗CSV（空值/范围/格式/去重） |
| 数据脱敏 | POST /api/data/desensitize | 自动识别手机号/身份证/银行卡并脱敏 |
| 金额脱敏 | POST /api/data/amount | 基于个位奇偶的金额脱敏（奇数上浮3%，偶数下浮3%） |
| MD5计算 | POST /api/data/md5 | 计算文本的MD5哈希 |

核心能力:
- 来自"数据清洗挑战"和"数据脱敏"CTF题目的实战经验
- 身份证校验码验证（加权求和法）
- CSV支持多种清洗规则组合
- 自动识别敏感数据类型

### 3.4 压缩包模块 (archive.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| ZIP分析 | POST /api/archive/analyze | 分析ZIP结构、文件列表、是否需要密码 |
| 密码爆破 | POST /api/archive/bruteforce | 内置80+CTF常见弱密码字典爆破 |
| 解压文件 | POST /api/archive/extract | 带密码解压并自动搜索flag |

核心能力:
- 内置80+个CTF高频密码（数字类、日期类、CTF特色类）
- 解压后自动扫描文件名和文件内容中的flag
- 支持RAR格式（需rarfile库）

### 3.5 图片隐写模块 (stego.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| 图片分析 | POST /api/stego/analyze | 提取字符串、flag、元数据、EXIF信息 |
| LSB隐写 | POST /api/stego/lsb | 提取RGB最低位隐藏信息 |
| 文件签名 | POST /api/stego/signature | 检测文件真实类型（可能改了扩展名） |

核心能力:
- 文件尾部附加数据检测
- LSB隐写自动提取
- 12种文件签名识别（PNG/JPEG/GIF/ZIP/RAR/ELF/PE/PDF等）

### 3.6 流量分析模块 (traffic.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| pcap分析 | POST /api/traffic/analyze | 协议统计、DNS查询、HTTP请求、凭据提取、flag搜索 |
| 字符串提取 | POST /api/traffic/strings | 从pcap中提取所有可打印字符串 |

核心能力:
- 协议统计（TCP/UDP/DNS）
- 自动提取: HTTP请求、Authorization头、Cookie、FTP凭据、SMTP明文、Telnet密码
- DNS查询记录提取
- Base64载荷自动解码
- 需要scapy库（未安装时有降级处理）

### 3.7 防火墙模块 (firewall.py) ✅

| 功能 | API路径 | 说明 |
|------|---------|------|
| 规则生成 | POST /api/firewall/generate | 根据场景生成iptables规则 |
| 场景列表 | GET /api/firewall/scenarios | 列出所有可用场景 |

支持的场景:
- 白名单_只允许指定IP
- 白名单_多IP
- 黑名单_禁止指定IP
- 端口限制_只开放指定端口
- 防SYN洪水攻击
- 防端口扫描
- NAT端口转发
- 限制特定端口访问频率
- 预设: web服务器 / 数据库服务器

### 3.8 Web安全模块 (web.py) ✅ 刚完成

| 功能 | API路径 | 说明 |
|------|---------|------|
| SQL注入payload | POST /api/web/sqli | 按数据库类型生成注入payload |
| 文件包含payload | POST /api/web/lfi | LFI/RFI payload + 绕过技巧 |
| sqlmap命令生成 | POST /api/web/sqlmap | 自动生成sqlmap命令 |

核心能力:
- 基础注入payload 11个
- MySQL专用payload 9个（联合查询、盲注、文件操作）
- MSSQL专用payload 4个
- 报错注入payload 3个
- LFI payload 10个（目录穿越、PHP伪协议、data协议）
- RFI payload 2个
- sqlmap命令自动生成（7种用法 + tamper脚本推荐）

### 3.9 智能检测 API (app.py 中的 /api/auto) ✅

自动识别输入类型并调用对应解题器:
- 文件: 根据扩展名自动选择（.exe→逆向、.zip→压缩包、.png→隐写、.pcap→流量、.csv→数据清洗、.xlsx→Excel分析）
- 文本: 自动尝试编码识别、哈希识别、多层解码、凯撒爆破、敏感数据检测

---

## 四、前端页面设计 (templates/index.html) ❌ 待开发

### 4.1 设计要求
- 暗色黑客风格主题（深色背景 + 绿色/青色高亮）
- 单文件HTML，内嵌CSS和JS，无外部依赖
- 标签页导航，9个功能模块
- 支持文件上传和文本输入两种模式
- 结果实时显示，支持JSON美化输出
- 移动端适配（响应式布局）

### 4.2 页面布局
```
┌─────────────────────────────────────────────────┐
│  🛡️ CTF工具箱          [智能检测]按钮   │
├─────────────────────────────────────────────────┤
│ [逆向] [密码学] [数据安全] [压缩包] [隐写]       │
│ [流量] [Web安全] [防火墙]                        │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │  输入区域: [文件上传] 或 [文本输入框]     │   │
│  │  [开始分析] 按钮                          │   │
│  └──────────────────────────────────────────┘   │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │  结果展示区域                              │   │
│  │  - 分模块折叠显示                          │   │
│  │  - Flag高亮显示（红色/黄色）               │   │
│  │  - JSON美化 + 复制按钮                     │   │
│  └──────────────────────────────────────────┘   │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 4.3 各模块前端交互设计

| 模块 | 输入方式 | 特殊交互 |
|------|----------|----------|
| 智能检测 | 文件/文本 | 一键全自动分析 |
| 逆向工程 | 文件上传 | 3个子功能按钮(分析/异或/找flag) |
| 密码学 | 文本输入 | 5个子功能按钮 + 编码类型下拉 |
| 数据安全 | 文本/文件 | 表单输入 + 规则配置面板 |
| 压缩包 | 文件上传 | 自动分析+爆破+解压 |
| 图片隐写 | 文件上传 | 3个子功能 + 图片预览 |
| 流量分析 | 文件上传 | 2个子功能 |
| Web安全 | 表单输入 | 数据库类型选择 + URL输入 |
| 防火墙 | 下拉选择 | 场景选择 + 变量输入表单 |

### 4.4 前端所需实现的功能
1. 顶部标题栏 + 项目说明
2. 标签页切换系统（9个tab）
3. 文件上传组件（支持拖拽）
4. 文本输入区域
5. API调用封装（fetch）
6. 结果渲染引擎（JSON美化、Flag高亮、折叠面板）
7. 防火墙场景的动态表单生成
8. 错误处理和加载状态显示
9. 暗色主题CSS

---

## 五、依赖安装

### 5.1 必需依赖
```bash
pip install flask
pip install pillow        # 图片隐写模块需要
```

### 5.2 可选依赖（增强功能）
```bash
pip install pefile         # PE文件深度分析
pip install scapy          # pcap流量分析
pip install rarfile        # RAR压缩包支持
pip install pandas         # Excel文件分析
```

### 5.3 无依赖降级方案
所有模块都设计了降级方案，即使不安装可选依赖也能运行基本功能:
- 无pefile → 退化为纯二进制字符串提取
- 无scapy → 退化为pcap原始字符串提取
- 无rarfile → 仅支持ZIP格式
- 无pandas → Excel分析不可用

---

## 六、当前进展总结

### ✅ 已完成 (后端 100%)
| 项目 | 状态 | 文件 | 行数 |
|------|------|------|------|
| Flask主程序 | ✅ | app.py | 485行 |
| 逆向工程模块 | ✅ | solvers/reverse.py | 171行 |
| 密码学模块 | ✅ | solvers/crypto.py | 244行 |
| 数据安全模块 | ✅ | solvers/data_sec.py | 241行 |
| 压缩包模块 | ✅ | solvers/archive.py | 132行 |
| 图片隐写模块 | ✅ | solvers/stego.py | 139行 |
| 流量分析模块 | ✅ | solvers/traffic.py | 140行 |
| 防火墙模块 | ✅ | solvers/firewall.py | 178行 |
| Web安全模块 | ✅ | solvers/web.py | ~200行 |

**后端总计: 约 1,930 行代码，8个解题模块，30+个API接口**

### ❌ 待完成 (前端 0%)
| 项目 | 状态 | 说明 |
|------|------|------|
| templates/index.html | ❌ 待开发 | 前端页面，包含9个功能模块的界面 |

---

## 七、API接口完整列表

### 逆向工程
```
POST /api/reverse/analyze     - PE文件分析（上传文件）
POST /api/reverse/xor         - 异或爆破（上传文件）
POST /api/reverse/find-flag   - 搜索flag（上传文件）
```

### 密码学
```
POST /api/crypto/identify     - 编码识别（JSON: {text}）
POST /api/crypto/caesar       - 凯撒爆破（JSON: {text}）
POST /api/crypto/md5          - MD5反查（JSON: {hash}）
POST /api/crypto/decode       - 多层解码（JSON: {text}）
POST /api/crypto/hash-id      - 哈希识别（JSON: {text}）
```

### 数据安全
```
POST /api/data/luhn           - Luhn校验（JSON: {number}）
POST /api/data/visa           - VISA校验（JSON: {number}）
POST /api/data/id-card        - 身份证校验（JSON: {id}）
POST /api/data/clean          - CSV清洗（上传文件 + rules参数）
POST /api/data/desensitize    - 数据脱敏（JSON: {text}）
POST /api/data/amount         - 金额脱敏（JSON: {amount}）
POST /api/data/md5            - MD5计算（JSON: {text}）
```

### 压缩包
```
POST /api/archive/analyze     - ZIP分析（上传文件）
POST /api/archive/bruteforce  - 密码爆破（上传文件）
POST /api/archive/extract     - 解压文件（上传文件 + password参数）
```

### 图片隐写
```
POST /api/stego/analyze       - 图片分析（上传文件）
POST /api/stego/lsb           - LSB隐写（上传文件）
POST /api/stego/signature     - 文件签名（上传文件）
```

### 流量分析
```
POST /api/traffic/analyze     - pcap分析（上传文件）
POST /api/traffic/strings     - 字符串提取（上传文件）
```

### Web安全
```
POST /api/web/sqli            - SQL注入payload（JSON: {db_type}）
POST /api/web/lfi             - 文件包含payload
POST /api/web/sqlmap          - sqlmap命令（JSON: {url, data, cookie, method}）
```

### 防火墙
```
POST /api/firewall/generate   - 生成规则（JSON: {scenario, config}）
GET  /api/firewall/scenarios  - 场景列表
```

### 智能检测
```
POST /api/auto                - 自动检测（文件或文本）
```

---

## 八、使用示例

### 示例1: 分析一个可疑EXE文件
1. 打开 http://127.0.0.1:5000
2. 切换到"逆向工程"标签
3. 上传EXE文件
4. 点击"PE文件分析" → 查看区段、资源段、导入表
5. 点击"搜索Flag" → 自动搜索flag{}格式字符串

### 示例2: 解码一段密文
1. 切换到"密码学"标签
2. 输入: SGVsbG8gV29ybGQ=
3. 点击"编码识别" → 识别为Base64，解码结果: Hello World
4. 或点击"多层解码" → 自动尝试多层剥离

### 示例3: 生成防火墙规则
1. 切换到"防火墙"标签
2. 选择场景: "白名单_只允许指定IP"
3. 填入IP: 192.168.1.100
4. 点击"生成规则" → 获得完整的iptables命令

---

*文档结束 - 下一步: 开发前端页面 templates/index.html*
