"""采购审批域：对外契约与缺陷开关。

一个业务域做深，而不是四个域做薄：状态机、金额阈值、审批链都在这儿定义。
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    EMPLOYEE = "employee"
    MANAGER = "manager"
    FINANCE = "finance"
    CFO = "cfo"
    AUDITOR = "auditor"


class Status(StrEnum):
    DRAFT = "DRAFT"
    MANAGER_REVIEW = "MANAGER_REVIEW"
    FINANCE_REVIEW = "FINANCE_REVIEW"
    CFO_REVIEW = "CFO_REVIEW"
    APPROVED = "APPROVED"
    PAID = "PAID"
    REJECTED = "REJECTED"


class DefectFlag(StrEnum):
    """业务缺陷开关。网关能拦的只有 SQLi / SSRF，其余必须改代码。"""

    SQLI_SEARCH = "sqli_search"
    SQLI_LOGIN_BYPASS = "sqli_login_bypass"
    IDOR_PO_DETAIL = "idor_po_detail"
    MASS_ASSIGNMENT = "mass_assignment"
    STATE_SKIP = "state_skip"
    PATH_TRAVERSAL = "path_traversal"
    SSRF_SUPPLIER = "ssrf_supplier"
    PAYMENT_AMOUNT_TAMPER = "payment_amount_tamper"
    PAYMENT_REPLAY = "payment_replay"
    PASSWORD_RESET_IDOR = "password_reset_idor"


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(max_length=128)


class LoginOut(BaseModel):
    token: str
    role: Role
    tenant: str
    department: str


class POSummary(BaseModel):
    id: int
    title: str
    amount: int
    status: Status
    requester: str


class POList(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[POSummary]


class ApprovalOut(BaseModel):
    actor: str
    role: str
    decision: str
    comment: str


class PODetail(BaseModel):
    id: int
    title: str
    amount: int
    status: Status
    requester: str
    supplier_id: int
    attachment: str
    notes: str = ""
    approvals: list[ApprovalOut] = Field(default_factory=list)


class CreatePO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=80)
    amount: int = Field(ge=1, le=10_000_000)
    supplier_id: int = Field(ge=1, le=999)


class ApproveIn(BaseModel):
    """审批输入。``approver`` 只在 mass_assignment 缺陷开启时才被信任。"""

    model_config = ConfigDict(extra="allow")

    decision: str = Field(pattern="^(approve|reject)$")
    comment: str = Field(default="", max_length=200)
    approver: str | None = None


class AttachmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    content: str = Field(max_length=4096)


class AttachmentOut(BaseModel):
    name: str
    stored_at: str
    size: int


class CallbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=512)


class CallbackOut(BaseModel):
    host: str
    path: str
    status: int
    preview: str


class AuditEntry(BaseModel):
    id: int
    ts: str
    actor: str
    role: str
    method: str
    path: str
    status: int


class MissionStatus(BaseModel):
    """任务目标：判定查数据库状态，不查响应文本。"""

    goal: str
    achieved: bool
    po_id: int | None = None
    approvals: int = 0
    detail: str


class SupplierOut(BaseModel):
    id: int
    name: str
    bank_account: str
    callback_url: str
    level: str


class PaymentIn(BaseModel):
    po_id: int
    amount: int
    idempotency_key: str = ""


class PaymentOut(BaseModel):
    id: int
    po_id: int
    amount: int
    expected_amount: int
    receipt_no: str
    duplicate: bool = False
    tampered: bool = False


class PasswordChangeIn(BaseModel):
    old_password: str
    new_password: str
    user_id: int | None = None


class PasswordChangeOut(BaseModel):
    ok: bool
    changed_user: str
