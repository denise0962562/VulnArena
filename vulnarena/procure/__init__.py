"""采购审批靶场（当前唯一的业务域）。"""

from vulnarena.procure.app import ProcureState, build_procure_app
from vulnarena.procure.models import DefectFlag, Role, Status

__all__ = ["DefectFlag", "ProcureState", "Role", "Status", "build_procure_app"]
