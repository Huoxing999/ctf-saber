"""数据库安全模块 - SQL语法生成、安全加固、数据库操作"""
import re
from solvers.common import find_flags_in_text


# ============ 竞赛一键场景 ============

def competition_db_task(task_num: int, config: dict = None) -> dict:
    """竞赛数据库题目一键生成"""
    if config is None:
        config = {}

    tasks = {
        1: {
            "name": "用户权限管理",
            "description": "创建数据库用户、授权、回收权限",
            "commands": [
                "# 创建数据库",
                "CREATE DATABASE IF NOT EXISTS company_db DEFAULT CHARSET utf8mb4;",
                "USE company_db;",
                "",
                "# 创建用户",
                "CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'P@ssw0rd2025!';",
                "CREATE USER 'readonly'@'localhost' IDENTIFIED BY 'ReadOnly@2025!';",
                "CREATE USER 'admin'@'localhost' IDENTIFIED BY 'Admin@2025!';",
                "",
                "# 授权",
                "GRANT SELECT, INSERT, UPDATE, DELETE ON company_db.* TO 'app_user'@'localhost';",
                "GRANT SELECT ON company_db.* TO 'readonly'@'localhost';",
                "GRANT ALL PRIVILEGES ON company_db.* TO 'admin'@'localhost';",
                "",
                "# 查看权限",
                "SHOW GRANTS FOR 'app_user'@'localhost';",
                "SHOW GRANTS FOR 'readonly'@'localhost';",
                "",
                "# 回收权限",
                "REVOKE DELETE ON company_db.* FROM 'app_user'@'localhost';",
                "",
                "# 刷新权限",
                "FLUSH PRIVILEGES;",
            ],
            "tips": [
                "密码要包含大小写字母+数字+特殊字符",
                "应用账户只授予必要权限，遵循最小权限原则",
                "FLUSH PRIVILEGES 使权限更改立即生效",
            ],
        },
        2: {
            "name": "建表与约束",
            "description": "创建含主键、外键、唯一约束、检查约束的表",
            "commands": [
                "# 创建数据库",
                "CREATE DATABASE IF NOT EXISTS school_db DEFAULT CHARSET utf8mb4;",
                "USE school_db;",
                "",
                "# 创建学生表",
                "CREATE TABLE Students (",
                "  StudentID INT PRIMARY KEY AUTO_INCREMENT,",
                "  Name VARCHAR(50) NOT NULL,",
                "  Age INT CHECK (Age >= 0 AND Age <= 150),",
                "  Gender ENUM('男', '女') NOT NULL,",
                "  Email VARCHAR(100) UNIQUE,",
                "  Major VARCHAR(100) NOT NULL,",
                "  EnrollmentDate DATE DEFAULT (CURRENT_DATE)",
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                "",
                "# 创建课程表",
                "CREATE TABLE Courses (",
                "  CourseID VARCHAR(20) PRIMARY KEY,",
                "  CourseName VARCHAR(100) NOT NULL,",
                "  Credits INT NOT NULL CHECK (Credits > 0),",
                "  Teacher VARCHAR(50)",
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                "",
                "# 创建选课表（外键）",
                "CREATE TABLE Enrollments (",
                "  ID INT PRIMARY KEY AUTO_INCREMENT,",
                "  StudentID INT NOT NULL,",
                "  CourseID VARCHAR(20) NOT NULL,",
                "  Grade DECIMAL(5,2) CHECK (Grade >= 0 AND Grade <= 100),",
                "  FOREIGN KEY (StudentID) REFERENCES Students(StudentID),",
                "  FOREIGN KEY (CourseID) REFERENCES Courses(CourseID),",
                "  UNIQUE KEY uk_student_course (StudentID, CourseID)",
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            ],
            "tips": [
                "PRIMARY KEY 主键自动带 NOT NULL 和 UNIQUE",
                "AUTO_INCREMENT 自增列只能是整数类型",
                "FOREIGN KEY 建立表间关系，保证数据完整性",
                "CHECK 约束限制列值范围（MySQL 8.0+支持）",
                "UNIQUE KEY 唯一约束允许NULL值",
            ],
            "variables": {},
        },
        3: {
            "name": "索引与性能优化",
            "description": "创建索引、查看执行计划、优化慢查询",
            "commands": [
                "# 创建普通索引",
                "CREATE INDEX idx_student_name ON Students(Name);",
                "",
                "# 创建复合索引",
                "CREATE INDEX idx_major_date ON Students(Major, EnrollmentDate);",
                "",
                "# 创建唯一索引",
                "CREATE UNIQUE INDEX idx_email ON Students(Email);",
                "",
                "# 查看表的索引",
                "SHOW INDEX FROM Students;",
                "",
                "# 查看执行计划",
                "EXPLAIN SELECT * FROM Students WHERE Major = '计算机科学';",
                "EXPLAIN SELECT * FROM Students WHERE Name = '张三';",
                "",
                "# 查看慢查询日志状态",
                "SHOW VARIABLES LIKE 'slow_query%';",
                "",
                "# 开启慢查询日志",
                "SET GLOBAL slow_query_log = 'ON';",
                "SET GLOBAL long_query_time = 1;",
                "",
                "# 分析表",
                "ANALYZE TABLE Students;",
                "",
                "# 优化表",
                "OPTIMIZE TABLE Students;",
            ],
            "tips": [
                "索引能加速查询但会降低写入性能",
                "复合索引遵循最左前缀原则",
                "EXPLAIN 查看执行计划，关注 type、key、rows 列",
                "type 从好到差: system > const > eq_ref > ref > range > index > ALL",
            ],
        },
        4: {
            "name": "视图与存储过程",
            "description": "创建视图、存储过程、触发器",
            "commands": [
                "# 创建视图",
                "CREATE VIEW v_student_grades AS",
                "SELECT s.Name, c.CourseName, e.Grade",
                "FROM Students s",
                "JOIN Enrollments e ON s.StudentID = e.StudentID",
                "JOIN Courses c ON e.CourseID = c.CourseID;",
                "",
                "# 使用视图",
                "SELECT * FROM v_student_grades WHERE Grade > 90;",
                "",
                "# 查看视图定义",
                "SHOW CREATE VIEW v_student_grades;",
                "",
                "# 创建存储过程",
                "DELIMITER //",
                "CREATE PROCEDURE sp_get_top_students(IN min_grade DECIMAL(5,2), IN limit_count INT)",
                "BEGIN",
                "  SELECT s.Name, AVG(e.Grade) AS AvgGrade",
                "  FROM Students s",
                "  JOIN Enrollments e ON s.StudentID = e.StudentID",
                "  GROUP BY s.StudentID, s.Name",
                "  HAVING AVG(e.Grade) >= min_grade",
                "  ORDER BY AvgGrade DESC",
                "  LIMIT limit_count;",
                "END //",
                "DELIMITER ;",
                "",
                "# 调用存储过程",
                "CALL sp_get_top_students(85, 10);",
                "",
                "# 创建触发器",
                "DELIMITER //",
                "CREATE TRIGGER trg_before_insert_grade",
                "BEFORE INSERT ON Enrollments",
                "FOR EACH ROW",
                "BEGIN",
                "  IF NEW.Grade < 0 OR NEW.Grade > 100 THEN",
                "    SIGNAL SQLSTATE '45000'",
                "    SET MESSAGE_TEXT = '成绩必须在0-100之间';",
                "  END IF;",
                "END //",
                "DELIMITER ;",
            ],
            "tips": [
                "视图是虚拟表，不存储数据，简化复杂查询",
                "存储过程可封装复杂业务逻辑，减少网络传输",
                "触发器在特定事件(INSERT/UPDATE/DELETE)时自动执行",
                "DELIMITER 用于修改语句结束符，避免与过程体中的分号冲突",
            ],
        },
        5: {
            "name": "数据库备份与恢复",
            "description": "备份数据库、恢复数据、导出导入",
            "commands": [
                "# 备份单个数据库",
                "mysqldump -u root -p school_db > school_db_backup.sql",
                "",
                "# 备份所有数据库",
                "mysqldump -u root -p --all-databases > all_backup.sql",
                "",
                "# 备份指定表",
                "mysqldump -u root -p school_db Students Courses > tables_backup.sql",
                "",
                "# 备份结构（不含数据）",
                "mysqldump -u root -p --no-data school_db > structure_only.sql",
                "",
                "# 备份数据（不含结构）",
                "mysqldump -u root -p --no-create-info school_db > data_only.sql",
                "",
                "# 恢复数据库",
                "mysql -u root -p school_db < school_db_backup.sql",
                "",
                "# 恢复所有数据库",
                "mysql -u root -p < all_backup.sql",
                "",
                "# 导出CSV",
                "SELECT * FROM Students INTO OUTFILE '/tmp/students.csv'",
                "FIELDS TERMINATED BY ',' ENCLOSED BY '\"'",
                "LINES TERMINATED BY '\\n';",
                "",
                "# 导入CSV",
                "LOAD DATA INFILE '/tmp/students.csv'",
                "INTO TABLE Students",
                "FIELDS TERMINATED BY ',' ENCLOSED BY '\"'",
                "LINES TERMINATED BY '\\n';",
            ],
            "tips": [
                "mysqldump 备份是逻辑备份，适合小型数据库",
                "定期备份是运维基本功，建议每日自动备份",
                "备份文件要存储在安全位置，最好异地备份",
                "恢复前先确认目标数据库是否存在",
            ],
        },
        6: {
            "name": "MySQL安全加固",
            "description": "MySQL数据库安全配置和加固",
            "commands": [
                "# 删除匿名用户",
                "DELETE FROM mysql.user WHERE User='';",
                "FLUSH PRIVILEGES;",
                "",
                "# 删除测试数据库",
                "DROP DATABASE IF EXISTS test;",
                "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';",
                "FLUSH PRIVILEGES;",
                "",
                "# 禁止root远程登录",
                "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');",
                "FLUSH PRIVILEGES;",
                "",
                "# 修改root密码",
                "ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStr0ng@P@ss!';",
                "FLUSH PRIVILEGES;",
                "",
                "# 禁用local_infile",
                "SET GLOBAL local_infile = 0;",
                "",
                "# 查看安全变量",
                "SHOW VARIABLES LIKE 'local_infile';",
                "SHOW VARIABLES LIKE 'secure_file_priv';",
                "SHOW VARIABLES LIKE 'sql_mode';",
                "",
                "# 设置sql_mode（严格模式）",
                "SET GLOBAL sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';",
            ],
            "tips": [
                "删除匿名用户防止未授权访问",
                "root账户必须设置强密码",
                "禁止root远程登录，仅允许本地登录",
                "local_infile=0 防止通过LOAD DATA读取服务器文件",
                "sql_mode 建议开启严格模式",
            ],
        },
        7: {
            "name": "事务与锁",
            "description": "事务控制、锁机制、并发处理",
            "commands": [
                "# 开启事务",
                "START TRANSACTION;",
                "",
                "# 执行操作",
                "UPDATE Accounts SET Balance = Balance - 1000 WHERE AccountID = 1;",
                "UPDATE Accounts SET Balance = Balance + 1000 WHERE AccountID = 2;",
                "",
                "# 提交事务",
                "COMMIT;",
                "",
                "# 回滚事务",
                "ROLLBACK;",
                "",
                "# 查看当前事务",
                "SELECT * FROM information_schema.INNODB_TRX;",
                "",
                "# 查看锁等待",
                "SELECT * FROM information_schema.INNODB_LOCK_WAITS;",
                "",
                "# 查看表锁状态",
                "SHOW STATUS LIKE 'Table_locks%';",
                "",
                "# 设置事务隔离级别",
                "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;",
                "",
                "# 查看隔离级别",
                "SELECT @@transaction_isolation;",
            ],
            "tips": [
                "START TRANSACTION 开启事务，COMMIT 提交，ROLLBACK 回滚",
                "事务保证ACID特性：原子性、一致性、隔离性、持久性",
                "四种隔离级别: READ UNCOMMITTED < READ COMMITTED < REPEATABLE READ < SERIALIZABLE",
                "MySQL默认隔离级别是 REPEATABLE READ",
            ],
        },
    }

    if task_num not in tasks:
        return {"success": False, "error": f"未知任务编号: {task_num}，可用: {list(tasks.keys())}"}

    task = tasks[task_num]
    result = {
        "success": True,
        "task_num": task_num,
        "name": task["name"],
        "description": task["description"],
        "commands": task["commands"],
        "tips": task.get("tips", []),
        "variables": task.get("variables", {}),
    }
    return result


def list_db_scenarios() -> dict:
    """列出所有数据库场景"""
    return {
        "success": True,
        "scenarios": {
            "user": {"name": "用户权限管理", "actions": ["create-user", "grant", "revoke", "show-grants", "drop-user"]},
            "table": {"name": "建表与约束", "actions": ["create", "alter", "drop", "show"]},
            "index": {"name": "索引优化", "actions": ["create-index", "show-index", "explain", "analyze"]},
            "view": {"name": "视图与存储过程", "actions": ["create-view", "create-procedure", "create-trigger"]},
            "backup": {"name": "备份恢复", "actions": ["dump", "restore", "export-csv", "import-csv"]},
            "security": {"name": "安全加固", "actions": ["checklist", "fix"]},
            "transaction": {"name": "事务与锁", "actions": ["commit", "rollback", "show-locks"]},
        },
        "competition_tasks": [1, 2, 3, 4, 5, 6, 7],
    }


def generate_create_table(table_name: str, columns: list, charset: str = "utf8mb4") -> dict:
    """生成CREATE TABLE语句"""
    if not table_name or not columns:
        return {"success": False, "error": "表名和列定义不能为空"}

    col_defs = []
    for col in columns:
        parts = [col.get("name", ""), col.get("type", "VARCHAR(255)")]
        if col.get("primary_key"):
            parts.append("PRIMARY KEY")
        if col.get("auto_increment"):
            parts.append("AUTO_INCREMENT")
        if col.get("not_null"):
            parts.append("NOT NULL")
        if col.get("default") is not None:
            parts.append(f"DEFAULT '{col['default']}'")
        if col.get("comment"):
            parts.append(f"COMMENT '{col['comment']}'")
        col_defs.append("  " + " ".join(parts))

    # 外键
    fk_defs = []
    for col in columns:
        if col.get("foreign_key"):
            fk = col["foreign_key"]
            fk_defs.append(f"  FOREIGN KEY ({col['name']}) REFERENCES {fk['table']}({fk['column']})")

    all_defs = col_defs + fk_defs
    sql = f"CREATE TABLE {table_name} (\n"
    sql += ",\n".join(all_defs)
    sql += f"\n) ENGINE=InnoDB DEFAULT CHARSET={charset};"

    return {"success": True, "sql": sql}


def generate_insert(table: str, data: dict) -> dict:
    """生成INSERT语句"""
    columns = ", ".join(data.keys())
    values = ", ".join(f"'{v}'" if isinstance(v, str) else str(v) for v in data.values())
    sql = f"INSERT INTO {table} ({columns}) VALUES ({values});"
    return {"success": True, "sql": sql}


def generate_update(table: str, data: dict, where: str) -> dict:
    """生成UPDATE语句"""
    sets = ", ".join(f"{k}='{v}'" if isinstance(v, str) else f"{k}={v}" for k, v in data.items())
    sql = f"UPDATE {table} SET {sets} WHERE {where};"
    return {"success": True, "sql": sql}


def generate_select(table: str, columns: str = "*", where: str = "", order_by: str = "", limit: int = 0) -> dict:
    """生成SELECT语句"""
    sql = f"SELECT {columns} FROM {table}"
    if where:
        sql += f" WHERE {where}"
    if order_by:
        sql += f" ORDER BY {order_by}"
    if limit > 0:
        sql += f" LIMIT {limit}"
    sql += ";"
    return {"success": True, "sql": sql}


def generate_join_query(tables: list, join_type: str = "INNER", group_by: str = "", having: str = "", count_col: str = "*") -> dict:
    """生成多表JOIN查询"""
    if len(tables) < 2:
        return {"success": False, "error": "至少需要2个表"}

    base = tables[0]
    sql = f"SELECT {base['columns']} FROM {base['name']}"

    for t in tables[1:]:
        sql += f"\n{join_type} JOIN {t['name']} ON {t['on']}"

    if group_by:
        sql += f"\nGROUP BY {group_by}"
    if having:
        sql += f"\nHAVING {having}"
    sql += ";"

    return {"success": True, "sql": sql}


def mysql_security_checklist() -> dict:
    """MySQL安全加固检查清单"""
    return {
        "success": True,
        "checklist": [
            {
                "name": "删除匿名用户",
                "severity": "高",
                "cmd": "SELECT User, Host FROM mysql.user WHERE User='';",
                "fix": "DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;",
                "check": "结果为空则安全"
            },
            {
                "name": "检查弱密码",
                "severity": "高",
                "cmd": "SELECT User, Host FROM mysql.user;",
                "fix": "ALTER USER 'user'@'host' IDENTIFIED BY 'StrongP@ss2025!';",
                "check": "所有用户应使用强密码"
            },
            {
                "name": "禁止root远程登录",
                "severity": "高",
                "cmd": "SELECT User, Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');",
                "fix": "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1'); FLUSH PRIVILEGES;",
                "check": "root只能本地登录"
            },
            {
                "name": "删除测试数据库",
                "severity": "中",
                "cmd": "SHOW DATABASES LIKE 'test';",
                "fix": "DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test'; FLUSH PRIVILEGES;",
                "check": "不应存在test数据库"
            },
            {
                "name": "最小权限原则",
                "severity": "高",
                "cmd": "SHOW GRANTS FOR 'webapp'@'localhost';",
                "fix": "CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'pass'; GRANT SELECT,INSERT ON mydb.* TO 'webapp'@'localhost';",
                "check": "应用账户只授予必要权限"
            },
            {
                "name": "禁用local_infile",
                "severity": "中",
                "cmd": "SHOW VARIABLES LIKE 'local_infile';",
                "fix": "SET GLOBAL local_infile = 0; (my.cnf: local_infile = 0)",
                "check": "值应为OFF"
            },
            {
                "name": "开启日志审计",
                "severity": "中",
                "cmd": "SHOW VARIABLES LIKE 'general_log';",
                "fix": "SET GLOBAL general_log = 'ON'; SET GLOBAL log_output = 'TABLE';",
                "check": "生产环境建议开启"
            },
            {
                "name": "限制文件权限",
                "severity": "高",
                "cmd": "SHOW VARIABLES LIKE 'secure_file_priv';",
                "fix": "my.cnf: secure_file_priv = /var/lib/mysql-files/",
                "check": "不应为空(允许任意路径)"
            },
        ],
        "用户角色建议": [
            {"role": "report_user", "grants": "SELECT only", "用途": "报表查询"},
            {"role": "app_user", "grants": "SELECT, INSERT, UPDATE", "用途": "应用操作"},
            {"role": "ops_user", "grants": "DDL + DML (no GRANT)", "用途": "运维操作"},
            {"role": "dba_user", "grants": "ALL PRIVILEGES", "用途": "数据库管理"},
        ],
        "配置文件加固项": [
            "bind-address = 127.0.0.1",
            "local_infile = 0",
            "safe-user-create = 1",
            "symbolic-links = 0",
            "skip-show-database",
            "log-error = /var/log/mysql/error.log",
            "slow_query_log = 1",
        ]
    }


def redis_security_checklist() -> dict:
    """Redis安全加固检查清单"""
    return {
        "success": True,
        "checklist": [
            {"name": "绑定地址", "cmd": "CONFIG GET bind", "fix": "bind 127.0.0.1", "check": "只绑定本地"},
            {"name": "设置密码", "cmd": "CONFIG GET requirepass", "fix": "requirepass YourStrongPassword!", "check": "必须设置密码"},
            {"name": "禁用CONFIG", "cmd": "CONFIG GET rename-command", "fix": "rename-command CONFIG ''", "check": "禁用或重命名"},
            {"name": "禁用FLUSHALL", "cmd": "", "fix": "rename-command FLUSHALL ''", "check": "禁用危险命令"},
            {"name": "禁用DEBUG", "cmd": "", "fix": "rename-command DEBUG ''", "check": "禁用调试命令"},
            {"name": "非root运行", "cmd": "ps aux | grep redis", "fix": "useradd -r -s /bin/false redis", "check": "不以root运行"},
            {"name": "禁用Lua脚本", "cmd": "", "fix": "rename-command EVAL ''", "check": "高安全场景禁用"},
        ]
    }


def generate_student_management_db() -> dict:
    """生成学生管理数据库建表语句(竞赛题)"""
    sql = """-- 创建数据库
CREATE DATABASE IF NOT EXISTS student_management DEFAULT CHARSET utf8mb4;
USE student_management;

-- 学生表
CREATE TABLE Students (
  StudentID INT PRIMARY KEY AUTO_INCREMENT,
  Name VARCHAR(50) NOT NULL,
  Age INT NOT NULL,
  Major VARCHAR(100) NOT NULL,
  EnrollmentDate DATE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 课程表
CREATE TABLE Courses (
  CourseID VARCHAR(20) PRIMARY KEY,
  CourseName VARCHAR(100) NOT NULL,
  Department VARCHAR(100) NOT NULL,
  Credits INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 选课表
CREATE TABLE Enrollments (
  EnrollmentID INT PRIMARY KEY AUTO_INCREMENT,
  StudentID INT NOT NULL,
  CourseID VARCHAR(20) NOT NULL,
  EnrollmentDate DATE,
  Grade DECIMAL(5,2),
  FOREIGN KEY (StudentID) REFERENCES Students(StudentID),
  FOREIGN KEY (CourseID) REFERENCES Courses(CourseID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 插入示例数据
INSERT INTO Students (Name, Age, Major, EnrollmentDate) VALUES
('张三', 20, '计算机科学', '2024-09-01'),
('李四', 21, '电子工程', '2024-09-01'),
('王五', 20, '计算机科学', '2024-09-01'),
('赵六', 22, '信息安全', '2024-09-01'),
('钱七', 21, '计算机网络', '2024-09-01'),
('孙八', 20, '电子工程', '2024-09-01'),
('周九', 21, '电子工程', '2024-09-01'),
('吴十', 22, '信息安全', '2024-09-01'),
('郑十一', 20, '计算机科学', '2024-09-01'),
('冯十二', 21, '计算机网络', '2024-09-01');

INSERT INTO Courses (CourseID, CourseName, Department, Credits) VALUES
('CS101', '程序设计基础', '计算机科学', 4),
('CS201', '数据结构', '计算机科学', 4),
('CS301', '操作系统', '计算机科学', 3),
('EE101', '电路原理', '电子工程', 3),
('EE201', '数字电路', '电子工程', 4),
('IS101', '信息安全导论', '信息安全', 3),
('IS201', '密码学', '信息安全', 3),
('CN101', '计算机网络', '计算机网络', 4),
('CN201', '网络安全', '计算机网络', 3),
('MA101', '高等数学', '数学', 5);

INSERT INTO Enrollments (StudentID, CourseID, EnrollmentDate, Grade) VALUES
(1, 'CS101', '2024-09-15', 92.5),
(1, 'CS201', '2024-09-15', 88.0),
(2, 'EE101', '2024-09-15', 85.5),
(2, 'EE201', '2024-09-15', 90.0),
(3, 'CS101', '2024-09-15', 95.0),
(3, 'CS301', '2024-09-15', 87.5),
(4, 'IS101', '2024-09-15', 91.0),
(4, 'IS201', '2024-09-15', 89.5),
(5, 'CN101', '2024-09-15', 78.0),
(5, 'CN201', '2024-09-15', 82.5),
(6, 'EE101', '2024-09-15', 76.0),
(7, 'EE201', '2024-09-15', 88.5),
(8, 'IS101', '2024-09-15', 93.0),
(9, 'CS101', '2024-09-15', 86.0),
(10, 'CN101', '2024-09-15', 80.0);"""

    queries = {
        "插入新学生": "INSERT INTO Students (Name, Age, Major, EnrollmentDate) VALUES ('李明', 19, '计算机网络', CURDATE());",
        "更新学生专业": "UPDATE Students SET Major='计算机科学' WHERE Name='周九';",
        "查询计算机科学课程": "SELECT * FROM Courses WHERE Department='计算机科学' ORDER BY CourseName ASC;",
        "统计选课人数": """SELECT c.CourseName, COUNT(e.StudentID) AS EnrollmentCount
FROM Courses c
LEFT JOIN Enrollments e ON c.CourseID = e.CourseID
GROUP BY c.CourseID, c.CourseName
ORDER BY EnrollmentCount DESC;""",
    }

    return {"success": True, "create_sql": sql, "common_queries": queries}


def sql_syntax_reference() -> dict:
    """SQL语法速查手册"""
    return {
        "success": True,
        "DDL": {
            "CREATE DATABASE": "CREATE DATABASE dbname DEFAULT CHARSET utf8mb4;",
            "CREATE TABLE": "CREATE TABLE t (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50) NOT NULL);",
            "ALTER TABLE ADD": "ALTER TABLE t ADD COLUMN age INT DEFAULT 0;",
            "ALTER TABLE DROP": "ALTER TABLE t DROP COLUMN age;",
            "DROP TABLE": "DROP TABLE IF EXISTS t;",
            "DROP DATABASE": "DROP DATABASE IF EXISTS dbname;",
        },
        "DML": {
            "INSERT": "INSERT INTO t (col1, col2) VALUES ('v1', 'v2');",
            "UPDATE": "UPDATE t SET col1='new' WHERE id=1;",
            "DELETE": "DELETE FROM t WHERE id=1;",
            "SELECT": "SELECT col1, col2 FROM t WHERE condition ORDER BY col1 LIMIT 10;",
        },
        "查询进阶": {
            "JOIN": "SELECT * FROM t1 INNER JOIN t2 ON t1.id=t2.t1_id;",
            "LEFT JOIN": "SELECT * FROM t1 LEFT JOIN t2 ON t1.id=t2.t1_id;",
            "GROUP BY": "SELECT col, COUNT(*) FROM t GROUP BY col HAVING COUNT(*)>1;",
            "子查询": "SELECT * FROM t WHERE id IN (SELECT t_id FROM t2);",
            "UNION": "SELECT col FROM t1 UNION SELECT col FROM t2;",
            "LIKE": "SELECT * FROM t WHERE name LIKE '%keyword%';",
            "BETWEEN": "SELECT * FROM t WHERE age BETWEEN 18 AND 30;",
            "IN": "SELECT * FROM t WHERE status IN (1,2,3);",
        },
        "权限管理": {
            "GRANT": "GRANT SELECT,INSERT ON db.* TO 'user'@'host';",
            "REVOKE": "REVOKE INSERT ON db.* FROM 'user'@'host';",
            "SHOW GRANTS": "SHOW GRANTS FOR 'user'@'host';",
            "FLUSH": "FLUSH PRIVILEGES;",
            "CREATE USER": "CREATE USER 'user'@'host' IDENTIFIED BY 'password';",
            "DROP USER": "DROP USER 'user'@'host';",
        },
        "加密函数": {
            "MD5": "SELECT MD5('text');",
            "SHA1": "SELECT SHA1('text');",
            "SHA2": "SELECT SHA2('text', 256);",
            "AES加密": "SELECT AES_ENCRYPT('plaintext', 'key');",
            "AES解密": "SELECT AES_DECRYPT(ciphertext, 'key');",
            "BASE64": "SELECT TO_BASE64('text'); SELECT FROM_BASE64('encoded');",
        }
    }


# ============ 竞赛SQL题模板库 ============

def competition_sql_templates() -> dict:
    """竞赛常见SQL题型模板库"""
    return {
        "success": True,
        "templates": [
            {
                "category": "建表与约束",
                "items": [
                    {
                        "title": "含主键、非空、唯一约束的建表",
                        "desc": "创建用户表，含主键自增、用户名唯一、邮箱非空",
                        "sql": """CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL,
  age INT DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""",
                        "知识点": "PRIMARY KEY, AUTO_INCREMENT, NOT NULL, UNIQUE, DEFAULT"
                    },
                    {
                        "title": "含外键的多表建表",
                        "desc": "创建订单系统：客户表+订单表+订单详情表",
                        "sql": """CREATE TABLE customers (
  customer_id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(50) NOT NULL,
  phone VARCHAR(20)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE orders (
  order_id INT PRIMARY KEY AUTO_INCREMENT,
  customer_id INT NOT NULL,
  order_date DATE NOT NULL,
  total_amount DECIMAL(10,2),
  FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE order_items (
  item_id INT PRIMARY KEY AUTO_INCREMENT,
  order_id INT NOT NULL,
  product_name VARCHAR(100),
  quantity INT NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""",
                        "知识点": "FOREIGN KEY, 多表关联, DECIMAL精度"
                    }
                ]
            },
            {
                "category": "JOIN多表查询",
                "items": [
                    {
                        "title": "INNER JOIN 内连接",
                        "desc": "查询所有有选课记录的学生姓名和课程名",
                        "sql": """SELECT s.Name, c.CourseName, e.Grade
FROM Students s
INNER JOIN Enrollments e ON s.StudentID = e.StudentID
INNER JOIN Courses c ON e.CourseID = c.CourseID;""",
                        "知识点": "INNER JOIN, 多表连接, 别名"
                    },
                    {
                        "title": "LEFT JOIN 左连接",
                        "desc": "查询所有学生及其选课数量（包括未选课的学生）",
                        "sql": """SELECT s.Name, COUNT(e.EnrollmentID) AS CourseCount
FROM Students s
LEFT JOIN Enrollments e ON s.StudentID = e.StudentID
GROUP BY s.StudentID, s.Name
ORDER BY CourseCount DESC;""",
                        "知识点": "LEFT JOIN, GROUP BY, COUNT"
                    },
                    {
                        "title": "自连接查询",
                        "desc": "查询选了同一门课的学生对",
                        "sql": """SELECT s1.Name AS Student1, s2.Name AS Student2, c.CourseName
FROM Enrollments e1
INNER JOIN Enrollments e2 ON e1.CourseID = e2.CourseID AND e1.StudentID < e2.StudentID
INNER JOIN Students s1 ON e1.StudentID = s1.StudentID
INNER JOIN Students s2 ON e2.StudentID = s2.StudentID
INNER JOIN Courses c ON e1.CourseID = c.CourseID;""",
                        "知识点": "自连接, 表别名, 条件避免重复"
                    }
                ]
            },
            {
                "category": "GROUP BY聚合统计",
                "items": [
                    {
                        "title": "HAVING过滤分组",
                        "desc": "查询平均成绩高于85分的课程",
                        "sql": """SELECT c.CourseName, AVG(e.Grade) AS AvgGrade, COUNT(e.StudentID) AS StudentCount
FROM Courses c
INNER JOIN Enrollments e ON c.CourseID = e.CourseID
GROUP BY c.CourseID, c.CourseName
HAVING AVG(e.Grade) > 85
ORDER BY AvgGrade DESC;""",
                        "知识点": "GROUP BY, HAVING, AVG, 聚合函数"
                    },
                    {
                        "title": "多列分组统计",
                        "desc": "按专业和性别统计学生人数",
                        "sql": """SELECT Major, Gender, COUNT(*) AS Count
FROM Students
GROUP BY Major, Gender
ORDER BY Major, Gender;""",
                        "知识点": "多列GROUP BY, COUNT(*)"
                    }
                ]
            },
            {
                "category": "子查询",
                "items": [
                    {
                        "title": "WHERE IN 子查询",
                        "desc": "查询选了'数据结构'课程的学生",
                        "sql": """SELECT * FROM Students
WHERE StudentID IN (
  SELECT StudentID FROM Enrollments
  WHERE CourseID = (SELECT CourseID FROM Courses WHERE CourseName = '数据结构')
);""",
                        "知识点": "WHERE IN, 嵌套子查询"
                    },
                    {
                        "title": "EXISTS 子查询",
                        "desc": "查询至少选了一门课的学生",
                        "sql": """SELECT * FROM Students s
WHERE EXISTS (
  SELECT 1 FROM Enrollments e WHERE e.StudentID = s.StudentID
);""",
                        "知识点": "EXISTS, 关联子查询"
                    },
                    {
                        "title": "FROM子查询（派生表）",
                        "desc": "查询每个专业平均分最高的学生",
                        "sql": """SELECT s.Name, s.Major, avg_scores.MaxGrade
FROM Students s
INNER JOIN (
  SELECT e.StudentID, MAX(e.Grade) AS MaxGrade
  FROM Enrollments e
  GROUP BY e.StudentID
) avg_scores ON s.StudentID = avg_scores.StudentID;""",
                        "知识点": "派生表, 子查询作为临时表"
                    }
                ]
            },
            {
                "category": "UNION合并查询",
                "items": [
                    {
                        "title": "UNION去重合并",
                        "desc": "查询所有计算机科学和信息安全的学生",
                        "sql": """SELECT Name, Major FROM Students WHERE Major = '计算机科学'
UNION
SELECT Name, Major FROM Students WHERE Major = '信息安全'
ORDER BY Name;""",
                        "知识点": "UNION去重, UNION ALL不去重"
                    }
                ]
            },
            {
                "category": "窗口函数",
                "items": [
                    {
                        "title": "ROW_NUMBER排名",
                        "desc": "按成绩给每个学生在各课程中排名",
                        "sql": """SELECT s.Name, c.CourseName, e.Grade,
  ROW_NUMBER() OVER (PARTITION BY e.CourseID ORDER BY e.Grade DESC) AS ranking
FROM Enrollments e
INNER JOIN Students s ON e.StudentID = s.StudentID
INNER JOIN Courses c ON e.CourseID = c.CourseID;""",
                        "知识点": "ROW_NUMBER(), OVER, PARTITION BY"
                    },
                    {
                        "title": "RANK与DENSE_RANK",
                        "desc": "按总成绩给学生排名（含并列）",
                        "sql": """SELECT s.Name, SUM(e.Grade) AS TotalGrade,
  RANK() OVER (ORDER BY SUM(e.Grade) DESC) AS rank_num,
  DENSE_RANK() OVER (ORDER BY SUM(e.Grade) DESC) AS dense_rank_num
FROM Students s
INNER JOIN Enrollments e ON s.StudentID = e.StudentID
GROUP BY s.StudentID, s.Name;""",
                        "知识点": "RANK(), DENSE_RANK(), SUM聚合"
                    }
                ]
            },
            {
                "category": "视图与存储过程",
                "items": [
                    {
                        "title": "CREATE VIEW",
                        "desc": "创建学生成绩汇总视图",
                        "sql": """CREATE VIEW student_grade_summary AS
SELECT s.StudentID, s.Name, s.Major,
  COUNT(e.EnrollmentID) AS CourseCount,
  AVG(e.Grade) AS AvgGrade,
  MAX(e.Grade) AS MaxGrade,
  MIN(e.Grade) AS MinGrade
FROM Students s
LEFT JOIN Enrollments e ON s.StudentID = e.StudentID
GROUP BY s.StudentID, s.Name, s.Major;""",
                        "知识点": "CREATE VIEW, 聚合函数组合"
                    },
                    {
                        "title": "存储过程",
                        "desc": "创建按专业查询学生的存储过程",
                        "sql": """DELIMITER //
CREATE PROCEDURE GetStudentsByMajor(IN major_name VARCHAR(100))
BEGIN
  SELECT * FROM Students WHERE Major = major_name;
END //
DELIMITER ;

-- 调用
CALL GetStudentsByMajor('计算机科学');""",
                        "知识点": "DELIMITER, CREATE PROCEDURE, IN参数"
                    },
                    {
                        "title": "触发器",
                        "desc": "插入成绩时自动检查范围(0-100)",
                        "sql": """DELIMITER //
CREATE TRIGGER check_grade BEFORE INSERT ON Enrollments
FOR EACH ROW
BEGIN
  IF NEW.Grade < 0 OR NEW.Grade > 100 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '成绩必须在0-100之间';
  END IF;
END //
DELIMITER ;""",
                        "知识点": "CREATE TRIGGER, BEFORE INSERT, SIGNAL"
                    }
                ]
            }
        ]
    }


# ============ SQL语句自动纠错 ============

def sql_validate(sql_text: str) -> dict:
    """SQL语句自动纠错检查"""
    errors = []
    warnings = []
    sql = sql_text.strip()

    if not sql:
        return {"success": False, "error": "SQL语句为空"}

    # 检查分号
    if not sql.endswith(';'):
        errors.append({"type": "missing_semicolon", "msg": "SQL语句末尾缺少分号(;)"})

    # 引号匹配
    single_quotes = sql.count("'")
    if single_quotes % 2 != 0:
        errors.append({"type": "quote_mismatch", "msg": "单引号不匹配，缺少闭合引号"})

    double_quotes = sql.count('"')
    if double_quotes % 2 != 0:
        errors.append({"type": "quote_mismatch", "msg": "双引号不匹配，缺少闭合引号"})

    # 括号匹配
    open_parens = sql.count('(')
    close_parens = sql.count(')')
    if open_parens != close_parens:
        errors.append({"type": "paren_mismatch", "msg": f"括号不匹配: 左括号{open_parens}个，右括号{close_parens}个"})

    # 关键字拼写检查
    sql_upper = sql.upper()
    common_typos = {
        'SELCT': 'SELECT', 'FORM': 'FROM', 'FRON': 'FROM',
        'WEHERE': 'WHERE', 'WHRE': 'WHERE', 'GRUOP': 'GROUP',
        'OEDER': 'ORDER', 'INSRT': 'INSERT', 'UDPATE': 'UPDATE',
        'DELTE': 'DELETE', 'CERATE': 'CREATE', 'TABL': 'TABLE',
        'IMARY': 'PRIMARY', 'FORIEGN': 'FOREIGN', 'CONSTARINT': 'CONSTRAINT',
    }
    for typo, correct in common_typos.items():
        if typo in sql_upper:
            errors.append({"type": "typo", "msg": f"可能的拼写错误: '{typo}' -> '{correct}'"})

    # 常见语法问题警告
    if 'WHERE' in sql_upper and 'DELETE' in sql_upper and 'WHERE' not in sql_upper.split('DELETE')[1][:20].upper():
        warnings.append("DELETE语句没有WHERE条件，将删除所有数据")

    if 'WHERE' in sql_upper and 'UPDATE' in sql_upper:
        update_part = sql_upper.split('SET')[1] if 'SET' in sql_upper else ''
        if 'WHERE' not in update_part:
            warnings.append("UPDATE语句没有WHERE条件，将更新所有行")

    # JOIN缺少ON
    if re.search(r'\bJOIN\b', sql_upper) and 'ON' not in sql_upper:
        warnings.append("JOIN缺少ON连接条件")

    # GROUP BY缺少聚合函数
    if 'GROUP BY' in sql_upper and not any(fn in sql_upper for fn in ['COUNT', 'SUM', 'AVG', 'MAX', 'MIN']):
        warnings.append("GROUP BY通常需要配合聚合函数使用")

    return {
        "success": True,
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "line_count": len(sql.split('\n')),
        "char_count": len(sql)
    }


# ============ 竞赛数据库设计题模板 ============

def competition_db_design(scenario: str) -> dict:
    """竞赛数据库设计题模板"""
    templates = {
        "student": {
            "name": "学生管理系统",
            "description": "管理学生、课程和选课信息",
            "entities": [
                {"name": "Students", "desc": "学生实体", "attrs": ["学号PK", "姓名", "年龄", "专业", "入学日期"]},
                {"name": "Courses", "desc": "课程实体", "attrs": ["课程号PK", "课程名", "开课院系", "学分"]},
                {"name": "Enrollments", "desc": "选课关系", "attrs": ["选课ID PK", "学号FK", "课程号FK", "选课日期", "成绩"]}
            ],
            "relationships": "Students 1:N Enrollments, Courses 1:N Enrollments",
            "create_sql": generate_student_management_db()["create_sql"],
            "common_queries": {
                "查询学生选课情况": "SELECT s.Name, c.CourseName, e.Grade FROM Students s JOIN Enrollments e ON s.StudentID=e.StudentID JOIN Courses c ON e.CourseID=c.CourseID;",
                "统计各专业人数": "SELECT Major, COUNT(*) AS Cnt FROM Students GROUP BY Major ORDER BY Cnt DESC;",
                "查询平均成绩>85的学生": "SELECT s.Name, AVG(e.Grade) AS AvgG FROM Students s JOIN Enrollments e ON s.StudentID=e.StudentID GROUP BY s.StudentID HAVING AVG(e.Grade)>85;",
                "查询未选课的学生": "SELECT * FROM Students WHERE StudentID NOT IN (SELECT StudentID FROM Enrollments);",
            }
        },
        "library": {
            "name": "图书管理系统",
            "description": "管理图书、读者和借阅信息",
            "entities": [
                {"name": "Books", "desc": "图书实体", "attrs": ["图书ID PK", "书名", "作者", "出版社", "ISBN", "库存量"]},
                {"name": "Readers", "desc": "读者实体", "attrs": ["读者ID PK", "姓名", "手机号", "邮箱", "注册日期"]},
                {"name": "BorrowRecords", "desc": "借阅记录", "attrs": ["记录ID PK", "图书IDFK", "读者IDFK", "借出日期", "应还日期", "归还日期"]}
            ],
            "relationships": "Books 1:N BorrowRecords, Readers 1:N BorrowRecords",
            "create_sql": """CREATE DATABASE IF NOT EXISTS library_db DEFAULT CHARSET utf8mb4;
USE library_db;

CREATE TABLE Books (
  BookID INT PRIMARY KEY AUTO_INCREMENT,
  Title VARCHAR(200) NOT NULL,
  Author VARCHAR(100) NOT NULL,
  Publisher VARCHAR(100),
  ISBN VARCHAR(20) UNIQUE,
  Stock INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE Readers (
  ReaderID INT PRIMARY KEY AUTO_INCREMENT,
  Name VARCHAR(50) NOT NULL,
  Phone VARCHAR(20),
  Email VARCHAR(100),
  RegisterDate DATE DEFAULT (CURRENT_DATE)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE BorrowRecords (
  RecordID INT PRIMARY KEY AUTO_INCREMENT,
  BookID INT NOT NULL,
  ReaderID INT NOT NULL,
  BorrowDate DATE NOT NULL,
  DueDate DATE NOT NULL,
  ReturnDate DATE,
  FOREIGN KEY (BookID) REFERENCES Books(BookID),
  FOREIGN KEY (ReaderID) REFERENCES Readers(ReaderID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 示例数据
INSERT INTO Books (Title, Author, Publisher, ISBN, Stock) VALUES
('数据库系统概论', '王珊', '高等教育出版社', '978-7-04-040664-7', 5),
('计算机网络', '谢希仁', '电子工业出版社', '978-7-121-30295-4', 3),
('操作系统概念', 'Abraham', '机械工业出版社', '978-7-111-60420-8', 4),
('数据结构', '严蔚敏', '清华大学出版社', '978-7-302-03314-1', 6),
('算法导论', 'Thomas', '机械工业出版社', '978-7-111-40701-0', 2);""",
            "common_queries": {
                "查询某读者借阅记录": "SELECT b.Title, br.BorrowDate, br.DueDate, br.ReturnDate FROM BorrowRecords br JOIN Books b ON br.BookID=b.BookID WHERE br.ReaderID=1;",
                "查询逾期未还": "SELECT r.Name, b.Title, br.DueDate FROM BorrowRecords br JOIN Readers r ON br.ReaderID=r.ReaderID JOIN Books b ON br.BookID=b.BookID WHERE br.ReturnDate IS NULL AND br.DueDate < CURDATE();",
                "统计图书借阅排行": "SELECT b.Title, COUNT(*) AS BorrowCount FROM BorrowRecords br JOIN Books b ON br.BookID=b.BookID GROUP BY br.BookID ORDER BY BorrowCount DESC LIMIT 10;",
            }
        },
        "shop": {
            "name": "商品订单系统",
            "description": "管理商品、客户和订单信息",
            "entities": [
                {"name": "Products", "desc": "商品实体", "attrs": ["商品ID PK", "商品名", "分类", "单价", "库存"]},
                {"name": "Customers", "desc": "客户实体", "attrs": ["客户ID PK", "姓名", "手机", "地址"]},
                {"name": "Orders", "desc": "订单实体", "attrs": ["订单ID PK", "客户IDFK", "下单时间", "总金额", "状态"]},
                {"name": "OrderItems", "desc": "订单明细", "attrs": ["明细ID PK", "订单IDFK", "商品IDFK", "数量", "单价"]}
            ],
            "relationships": "Customers 1:N Orders, Orders 1:N OrderItems, Products 1:N OrderItems",
            "create_sql": """CREATE DATABASE IF NOT EXISTS shop_db DEFAULT CHARSET utf8mb4;
USE shop_db;

CREATE TABLE Products (
  ProductID INT PRIMARY KEY AUTO_INCREMENT,
  ProductName VARCHAR(100) NOT NULL,
  Category VARCHAR(50),
  Price DECIMAL(10,2) NOT NULL,
  Stock INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE Customers (
  CustomerID INT PRIMARY KEY AUTO_INCREMENT,
  Name VARCHAR(50) NOT NULL,
  Phone VARCHAR(20),
  Address VARCHAR(200)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE Orders (
  OrderID INT PRIMARY KEY AUTO_INCREMENT,
  CustomerID INT NOT NULL,
  OrderTime DATETIME DEFAULT CURRENT_TIMESTAMP,
  TotalAmount DECIMAL(10,2),
  Status ENUM('待付款','已付款','已发货','已完成','已取消') DEFAULT '待付款',
  FOREIGN KEY (CustomerID) REFERENCES Customers(CustomerID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE OrderItems (
  ItemID INT PRIMARY KEY AUTO_INCREMENT,
  OrderID INT NOT NULL,
  ProductID INT NOT NULL,
  Quantity INT NOT NULL,
  UnitPrice DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (OrderID) REFERENCES Orders(OrderID),
  FOREIGN KEY (ProductID) REFERENCES Products(ProductID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 示例数据
INSERT INTO Products (ProductName, Category, Price, Stock) VALUES
('机械键盘', '电脑外设', 299.00, 50),
('无线鼠标', '电脑外设', 89.00, 100),
('显示器', '电脑配件', 1299.00, 30),
('耳机', '数码配件', 199.00, 80),
('U盘64GB', '存储设备', 49.00, 200);""",
            "common_queries": {
                "查询订单详情": "SELECT o.OrderID, c.Name, p.ProductName, oi.Quantity, oi.UnitPrice FROM Orders o JOIN Customers c ON o.CustomerID=c.CustomerID JOIN OrderItems oi ON o.OrderID=oi.OrderID JOIN Products p ON oi.ProductID=p.ProductID WHERE o.OrderID=1;",
                "统计月销售额": "SELECT DATE_FORMAT(OrderTime,'%Y-%m') AS Month, SUM(TotalAmount) AS Sales FROM Orders WHERE Status='已完成' GROUP BY Month ORDER BY Month DESC;",
                "查询热销商品TOP5": "SELECT p.ProductName, SUM(oi.Quantity) AS TotalSold FROM OrderItems oi JOIN Products p ON oi.ProductID=p.ProductID GROUP BY p.ProductID ORDER BY TotalSold DESC LIMIT 5;",
            }
        },
        "employee": {
            "name": "员工薪资系统",
            "description": "管理员工、部门和薪资信息",
            "entities": [
                {"name": "Departments", "desc": "部门实体", "attrs": ["部门ID PK", "部门名", "楼层"]},
                {"name": "Employees", "desc": "员工实体", "attrs": ["员工ID PK", "姓名", "部门IDFK", "职位", "入职日期", "基本工资"]},
                {"name": "SalaryRecords", "desc": "薪资记录", "attrs": ["记录ID PK", "员工IDFK", "月份", "基本工资", "奖金", "扣款", "实发"]}
            ],
            "relationships": "Departments 1:N Employees, Employees 1:N SalaryRecords",
            "create_sql": """CREATE DATABASE IF NOT EXISTS employee_db DEFAULT CHARSET utf8mb4;
USE employee_db;

CREATE TABLE Departments (
  DeptID INT PRIMARY KEY AUTO_INCREMENT,
  DeptName VARCHAR(50) NOT NULL,
  Floor INT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE Employees (
  EmpID INT PRIMARY KEY AUTO_INCREMENT,
  Name VARCHAR(50) NOT NULL,
  DeptID INT NOT NULL,
  Position VARCHAR(50),
  HireDate DATE NOT NULL,
  BaseSalary DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (DeptID) REFERENCES Departments(DeptID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE SalaryRecords (
  RecordID INT PRIMARY KEY AUTO_INCREMENT,
  EmpID INT NOT NULL,
  PayMonth VARCHAR(7) NOT NULL,
  BaseSalary DECIMAL(10,2) NOT NULL,
  Bonus DECIMAL(10,2) DEFAULT 0,
  Deduction DECIMAL(10,2) DEFAULT 0,
  NetPay DECIMAL(10,2) GENERATED ALWAYS AS (BaseSalary + Bonus - Deduction) STORED,
  FOREIGN KEY (EmpID) REFERENCES Employees(EmpID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 示例数据
INSERT INTO Departments (DeptName, Floor) VALUES ('技术部', 3), ('市场部', 5), ('财务部', 4), ('人事部', 2);

INSERT INTO Employees (Name, DeptID, Position, HireDate, BaseSalary) VALUES
('张工', 1, '高级工程师', '2020-03-15', 15000.00),
('李经理', 2, '市场总监', '2019-06-01', 18000.00),
('王会计', 3, '财务主管', '2021-01-10', 12000.00),
('赵HR', 4, '人事专员', '2022-07-20', 10000.00),
('陈开发', 1, '初级工程师', '2023-09-01', 8000.00);""",
            "common_queries": {
                "查询部门平均薪资": "SELECT d.DeptName, AVG(e.BaseSalary) AS AvgSalary FROM Departments d JOIN Employees e ON d.DeptID=e.DeptID GROUP BY d.DeptID;",
                "查询薪资最高员工": "SELECT Name, Position, BaseSalary FROM Employees ORDER BY BaseSalary DESC LIMIT 1;",
                "统计各部门人数": "SELECT d.DeptName, COUNT(e.EmpID) AS EmpCount FROM Departments d LEFT JOIN Employees e ON d.DeptID=e.DeptID GROUP BY d.DeptID;",
            }
        }
    }

    if scenario not in templates:
        return {"success": False, "error": f"未知场景: {scenario}，可用: {list(templates.keys())}"}

    return {"success": True, **templates[scenario]}
