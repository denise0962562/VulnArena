"""Target registry: one pluggable module per language.

Every language gets its own business scenario; what they share is a thin contract
at the HTTP boundary (defect header, canary marker, error shape, statelessness).
Adding a language means adding one manifest entry plus one small service.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from vulnarena.procure.models import DefectFlag


class TargetKind(StrEnum):
    IN_PROCESS = "in_process"
    HTTP = "http"


class TargetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    language: str
    scenario: str
    kind: TargetKind
    base_path: str
    port: int | None = None
    enabled: bool = False
    defects: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    notes: str = ""


PURCHASE_DEFECTS = [flag.value for flag in DefectFlag]

DEFAULT_TARGETS: list[TargetManifest] = [
    TargetManifest(
        id="python-procure",
        language="Python",
        scenario="企业采购审批：角色分工、金额阈值、三级审批、付款与审计",
        kind=TargetKind.IN_PROCESS,
        base_path="/api/procure",
        enabled=True,
        defects=PURCHASE_DEFECTS,
        endpoints=[
            "/login",
            "/pos",
            "/pos/{id}",
            "/pos/{id}/approve",
            "/pos/{id}/pay",
            "/suppliers/{id}",
            "/suppliers/{id}/callback-test",
            "/attachments",
            "/audit",
            "/mission",
        ],
        notes="参照实现：契约在这里定义，其余语言照此对齐",
    ),
    TargetManifest(
        id="go-gateway",
        language="Go",
        scenario="云原生边缘网关：对象存储预签名、流式转发、上游健康检查",
        kind=TargetKind.HTTP,
        base_path="/api/lab/go",
        port=8101,
        defects=["ssrf_upstream", "signed_url_bypass", "path_normalisation"],
        endpoints=["/sign", "/fetch", "/healthz"],
        notes="标准库 net/http，单二进制，无第三方依赖",
    ),
    TargetManifest(
        id="php-cms",
        language="PHP",
        scenario="传统建站：CMS 内容管理、附件上传、模板渲染",
        kind=TargetKind.HTTP,
        base_path="/api/lab/php",
        port=8102,
        defects=["sqli_search", "file_include", "upload_traversal"],
        endpoints=["/login", "/search", "/upload", "/render"],
        notes="php -S 内置服务器，最贴近真实建站现场",
    ),
    TargetManifest(
        id="java-ledger",
        language="Java",
        scenario="交易与账务：账户余额、并发扣款、订单状态机",
        kind=TargetKind.HTTP,
        base_path="/api/lab/java",
        port=8103,
        defects=["idor_account", "race_condition", "mass_assignment"],
        endpoints=["/accounts/{id}", "/transfer", "/orders/{id}"],
        notes="JDK 自带 com.sun.net.httpserver，零第三方依赖",
    ),
]


class TargetRegistry:
    def __init__(self, targets: list[TargetManifest] | None = None) -> None:
        self._targets: dict[str, TargetManifest] = {
            target.id: target for target in (targets or DEFAULT_TARGETS)
        }

    def all(self) -> list[TargetManifest]:
        return list(self._targets.values())

    def enabled(self) -> list[TargetManifest]:
        return [target for target in self._targets.values() if target.enabled]

    def get(self, target_id: str) -> TargetManifest | None:
        return self._targets.get(target_id)
