"""关卡：把缺陷组合包装成可解锁的题目。

设计参考：
* PortSwigger Academy —— 按漏洞类目分档、一个 lab 只教一件事，并有 Mystery Lab
  （隐藏题目描述，只给目标，练侦察与判断）
* Hack The Box —— 难度映射成分数，分数累积成段位

判定只看攻击的副作用（canary / 数据库状态），不看提交的 flag。
"""

from pydantic import BaseModel, Field

from vulnarena.arena.contracts import ArenaSession
from vulnarena.procure.models import DefectFlag


class Level(BaseModel):
    id: str
    tier: int
    title: str
    goal: str
    teaches: str
    defects: list[str]
    category: str
    points: int
    difficulty: str = "apprentice"
    unlock_after: str | None = None
    check: str
    mystery: bool = False


LEVELS: list[Level] = [
    Level(
        id="auth-bypass",
        tier=1,
        title="身份边界",
        goal="不输入正确密码，拿到一个高管会话",
        teaches="登录框把用户名拼进 SQL：注释掉密码校验，身份就变了",
        defects=[DefectFlag.SQLI_LOGIN_BYPASS.value],
        category="sqli",
        points=10,
        difficulty="apprentice",
        check="响应里的 role 变成 cfo",
    ),
    Level(
        id="data-injection",
        tier=2,
        title="注入与数据泄露",
        goal="让采购单搜索返回 secrets 表里的内容",
        teaches="LIKE 拼接 + UNION 查询：先数列数，再构造等列数的联合查询",
        defects=[DefectFlag.SQLI_SEARCH.value],
        category="sqli",
        points=20,
        difficulty="apprentice",
        unlock_after="auth-bypass",
        check="响应里出现 canary",
    ),
    Level(
        id="broken-access",
        tier=3,
        title="越权访问",
        goal="读到一张不属于你的采购单（含内部备注）",
        teaches="详情接口只认 id：换一个别人的单号就够了",
        defects=[DefectFlag.IDOR_PO_DETAIL.value],
        category="idor",
        points=30,
        difficulty="practitioner",
        unlock_after="data-injection",
        check="响应里出现 canary（别人的预算科目）",
    ),
    Level(
        id="logic-flaw",
        tier=4,
        title="业务逻辑",
        goal="让一张 ≥80 万的单据只经一人之手就变成已付款",
        teaches="审批接口信任请求体里的 approver，且不校验状态机",
        defects=[DefectFlag.MASS_ASSIGNMENT.value, DefectFlag.STATE_SKIP.value],
        category="logic",
        points=40,
        difficulty="practitioner",
        unlock_after="broken-access",
        check="mission 接口返回 achieved=true",
    ),
    Level(
        id="exposure",
        tier=5,
        title="暴露面",
        goal="读出付款网关密钥，或让服务器替你访问内网",
        teaches="附件路径未归一化 + 回调地址未限制，两个方向都能出网",
        defects=[DefectFlag.PATH_TRAVERSAL.value, DefectFlag.SSRF_SUPPLIER.value],
        category="path_traversal",
        points=50,
        difficulty="expert",
        unlock_after="logic-flaw",
        check="响应里出现 canary（密钥或元数据凭证）",
    ),
    Level(
        id="mystery",
        tier=6,
        title="神秘关卡",
        goal="目标不告诉你：自己找出这套系统的问题",
        teaches="真实项目没人给你题目描述，先侦察、再判断、最后动手",
        defects=[
            DefectFlag.SQLI_SEARCH.value,
            DefectFlag.IDOR_PO_DETAIL.value,
            DefectFlag.MASS_ASSIGNMENT.value,
            DefectFlag.STATE_SKIP.value,
        ],
        category="any",
        points=60,
        difficulty="expert",
        unlock_after="exposure",
        check="任意一类缺陷被击穿即可",
        mystery=True,
    ),
]

BY_ID = {level.id: level for level in LEVELS}


class LevelProgress(BaseModel):
    id: str
    tier: int
    title: str
    goal: str
    teaches: str
    points: int
    difficulty: str
    solved: bool = False
    unlocked: bool = True
    score: int = 0
    hints: int = 0
    evidence: str = ""
    defects: list[str] = Field(default_factory=list)


def score_for(level: Level, hints: int) -> int:
    """提示有成本：每用一次打七折，最低保留四成。"""
    factor = max(0.4, 0.7**hints)
    return int(round(level.points * factor))


def progress(sessions: list[ArenaSession]) -> list[LevelProgress]:
    """根据历史演练判断每一层是否被击穿、拿了多少分。"""
    best: dict[str, tuple[int, str]] = {}  # level_id -> (score, evidence)

    for session in sessions:
        level_id = getattr(session, "level_id", "") or ""
        hints = getattr(session, "hint_uses", 0) or 0
        level = BY_ID.get(level_id)
        for trace in session.traces:
            if not trace.breached:
                continue
            matched = level if level is not None else _match_by_category(trace.category)
            if matched is None:
                continue
            if matched.id in best:
                continue
            score = score_for(matched, hints)
            best[matched.id] = (
                score,
                f"{session.session_id} / 第 {trace.step} 步：{trace.label}",
            )

    items: list[LevelProgress] = []
    previous_solved = True
    for level in LEVELS:
        entry = best.get(level.id)
        item = LevelProgress(
            id=level.id,
            tier=level.tier,
            title=level.title,
            goal=level.goal,
            teaches=level.teaches,
            points=level.points,
            difficulty=level.difficulty,
            solved=entry is not None,
            unlocked=previous_solved,
            score=entry[0] if entry else 0,
            evidence=entry[1] if entry else "",
            defects=level.defects,
        )
        previous_solved = item.solved
        items.append(item)
    return items


def _match_by_category(category: str | None) -> Level | None:
    for level in LEVELS:
        if level.mystery:
            continue
        if level.category == category:
            return level
    return None


def total_score(items: list[LevelProgress]) -> int:
    return sum(item.score for item in items)


def rank(score: int) -> str:
    if score >= 180:
        return "红队队长"
    if score >= 120:
        return "渗透测试员"
    if score >= 60:
        return "安全分析员"
    if score > 0:
        return "观察员"
    return "新人"
