"""采购域的种子数据：同一份输入永远得到同一套数据。

数据之间是有因果的：采购单指向供应商，审批记录挂在单子上，附件用单号命名。
"""

import hashlib
import sqlite3

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    department TEXT NOT NULL,
    phone TEXT NOT NULL,
    tenant TEXT NOT NULL
);
CREATE TABLE suppliers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    bank_account TEXT NOT NULL,
    callback_url TEXT NOT NULL,
    level TEXT NOT NULL
);
CREATE TABLE purchase_orders (
    id INTEGER PRIMARY KEY,
    tenant TEXT NOT NULL,
    requester TEXT NOT NULL,
    title TEXT NOT NULL,
    amount INTEGER NOT NULL,
    supplier_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    attachment TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_id INTEGER NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    decision TEXT NOT NULL,
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL
);
CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '',
    receipt_no TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

USERS = [
    ("alice", "employee", "采购部", "13800000011", "T1", "alice-pw"),
    ("bob", "employee", "采购部", "13800000012", "T1", "bob-pw"),
    ("mike", "manager", "采购部", "13800000013", "T1", "mike-pw"),
    ("fiona", "finance", "财务部", "13800000014", "T1", "fiona-pw"),
    ("admin", "cfo", "管理层", "13800000015", "T1", "admin-pw"),
    ("guard", "auditor", "内审", "13800000016", "T1", "guard-pw"),
]

SUPPLIERS = [
    ("北京云图科技", "6222-0001-0001-0001", "http://hooks.internal/ingest", "normal"),
    ("上海励行咨询", "6222-0002-0002-0002", "http://hooks.internal/ingest", "normal"),
    ("深圳恒信设备", "6222-0003-0003-0003", "http://hooks.internal/ingest", "normal"),
]

ORDERS = [
    ("研发部显示器 8 台", 32_000, 1, "PAID", "mike", "2026-10-01"),
    ("差旅报销 9 月", 12_400, 3, "PAID", "alice", "2026-10-03"),
    ("外部渗透测试服务", 180_000, 2, "APPROVED", "bob", "2026-10-08"),
    ("安全设备采购", 460_000, 3, "FINANCE_REVIEW", "alice", "2026-10-12"),
    ("年会场地租赁", 88_000, 2, "MANAGER_REVIEW", "bob", "2026-10-15"),
    ("办公家具补采", 21_000, 1, "MANAGER_REVIEW", "alice", "2026-10-18"),
    ("数据标注外包", 96_000, 2, "DRAFT", "bob", "2026-10-20"),
    ("机房 UPS 更换", 310_000, 3, "CFO_REVIEW", "alice", "2026-10-22"),
]


def digest(password: str, pepper: str) -> str:
    return hashlib.sha256(f"{pepper}:{password}".encode()).hexdigest()


def build(conn: sqlite3.Connection, *, canary: str, pepper: str) -> None:
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO users (name, role, department, phone, tenant, password_hash)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (name, role, dept, phone, tenant, digest(pwd, pepper))
            for name, role, dept, phone, tenant, pwd in USERS
        ],
    )
    conn.executemany(
        "INSERT INTO suppliers (name, bank_account, callback_url, level) VALUES (?, ?, ?, ?)",
        SUPPLIERS,
    )

    rows = []
    for index, (title, amount, supplier, status, requester, created) in enumerate(ORDERS, start=1):
        # 大额单据带内部备注，备注里有 canary：越权读到它就算击穿
        notes = f"内部备注：预算科目 A-07；canary={canary}" if index in (4, 8) else "常规采购"
        rows.append(
            (
                index,
                "T1",
                requester,
                title,
                amount,
                supplier,
                status,
                f"invoice-{index:03d}.pdf",
                notes,
                f"{created}T09:00:00Z",
            )
        )
    conn.executemany(
        "INSERT INTO purchase_orders"
        " (id, tenant, requester, title, amount, supplier_id, status, attachment, notes,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )

    # 已存在的审批记录：让历史单据看起来真的被审批过。
    seed_approvals = [
        (1, "mike", "manager", "approve", "金额合规", "2026-10-01"),
        (1, "fiona", "finance", "approve", "已核对发票", "2026-10-02"),
        (1, "admin", "cfo", "approve", "同意", "2026-10-02"),
        (2, "mike", "manager", "approve", "差旅标准内", "2026-10-03"),
        (3, "mike", "manager", "approve", "安全预算", "2026-10-08"),
        (3, "fiona", "finance", "approve", "合同已归档", "2026-10-09"),
        (4, "mike", "manager", "approve", "设备老化", "2026-10-12"),
        (8, "mike", "manager", "approve", "机房整改", "2026-10-22"),
        (8, "fiona", "finance", "approve", "预算内", "2026-10-23"),
    ]
    conn.executemany(
        "INSERT INTO approvals (po_id, actor, role, decision, comment, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (po, actor, role, decision, comment, f"{day}T10:00:00Z")
            for po, actor, role, decision, comment, day in seed_approvals
        ],
    )

    conn.execute(
        "INSERT INTO secrets (name, value) VALUES (?, ?)",
        ("bank_gateway_key", f"bgw_live_{canary}"),
    )
    conn.execute(
        "INSERT INTO secrets (name, value) VALUES (?, ?)",
        ("supplier_api_token", f"sup_live_{canary}"),
    )
    conn.commit()


def build_files(canary: str) -> dict[str, str]:
    return {
        "/invoices/invoice-001.pdf": "%PDF-1.4 invoice 001\n",
        "/invoices/invoice-002.pdf": "%PDF-1.4 invoice 002\n",
        "/uploads/README.txt": "uploaded attachments live in memory\n",
        "/etc/procure/bank_gateway_key": f"bgw_live_{canary}\n",
    }
