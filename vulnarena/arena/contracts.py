"""Types shared by the four arena stages."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnarena.arena.gate import GateResult
from vulnarena.arena.policy import WafPolicy, WafRule
from vulnarena.schemas import utcnow

Actor = Literal["alice", "bob", "admin", "anonymous"]
BlockedBy = Literal["waf", "authorization", "none"]


class HttpCall(BaseModel):
    """A replayable request: enough to resend it byte for byte."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST"]
    path: str
    params: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None
    actor: Actor = "alice"


class ProbeTrace(BaseModel):
    step: int
    label: str
    category: str | None = None
    call: HttpCall
    status: int
    elapsed_ms: int
    rule_id: str | None = None
    canary_hit: bool = False
    breached: bool = False
    blocked_by: BlockedBy = "none"
    reasoning: str = ""


class DefensePatch(BaseModel):
    rule: WafRule | None = None
    rules: list[WafRule] = Field(default_factory=list)
    gate: GateResult | None = None
    gates: list[GateResult] = Field(default_factory=list)
    switched_flags: list[str] = Field(default_factory=list)
    diff: str = ""
    rationale: str = ""


class RegressionResult(BaseModel):
    attack_blocked: int = 0
    attack_total: int = 0
    missed: list[str] = Field(default_factory=list)
    benign_allowed: int = 0
    benign_total: int = 0
    false_positives: list[str] = Field(default_factory=list)
    passed: bool = False


class ArenaStatus(StrEnum):
    CREATED = "CREATED"
    BLUEPRINT_READY = "BLUEPRINT_READY"
    PROBING = "PROBING"
    BREACH_CONFIRMED = "BREACH_CONFIRMED"
    BREACH_FAILED = "BREACH_FAILED"
    PATCHING = "PATCHING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    REGRESSION_FAILED = "REGRESSION_FAILED"


class ArenaSnapshot(BaseModel):
    """Everything needed to put the range back into its vulnerable state."""

    defects: list[str] = Field(default_factory=list)
    policy: WafPolicy | None = None
    seed_version: str = "v1"


class GuideStep(BaseModel):
    """One hands-on step a learner can copy, run and compare."""

    index: int
    title: str
    intent: str
    brief: str = ""
    hint: str = ""
    request: HttpCall
    curl: str
    powershell: str
    expected_status: int
    expected_marker: str
    explanation: str
    defense_note: str


class BlueAction(BaseModel):
    """蓝队在一个回合里的响应。被闸门否决也要记下来，那是真实发生的。"""

    after_step: int
    regex: str = ""
    rule_id: str | None = None
    accepted: bool = False
    reason: str = ""
    source: str = "template"


class Round(BaseModel):
    index: int
    step: int
    label: str
    result: str
    blue: BlueAction | None = None


class ArenaSession(BaseModel):
    session_id: str
    status: ArenaStatus = ArenaStatus.CREATED
    agent_mode: str = "deterministic"
    plan_rationale: str = ""
    level_id: str = ""
    hint_uses: int = 0
    rounds: list[Round] = Field(default_factory=list)
    defects: list[str] = Field(default_factory=list)
    traces: list[ProbeTrace] = Field(default_factory=list)
    patch: DefensePatch | None = None
    regression: RegressionResult | None = None
    snapshot: ArenaSnapshot | None = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
