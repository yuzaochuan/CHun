"""Blind-oriented FMT facade."""

from __future__ import annotations

from ...core.models import (
    FmtExecutionResult,
    FmtTaskPolicy,
    FmtWriteComparison,
    FmtWritesComparison,
    FmtWritePlan,
)


class BlindFmtService:
    """为 blind/reconnect 场景提供默认的 BY_ATOM 行为。"""

    def __init__(self, session: object, *, base: object) -> None:
        self.session = session
        self.base = base

    def plan_write(self, target: object, value: object, **kwargs: object) -> FmtWritePlan:
        kwargs.setdefault("task_policy", FmtTaskPolicy.BY_ATOM)
        return self.base.plan_write(target, value, **kwargs)

    def plan_writes(self, writes: object, **kwargs: object) -> FmtWritePlan:
        kwargs.setdefault("task_policy", FmtTaskPolicy.BY_ATOM)
        return self.base.plan_writes(writes, **kwargs)

    def write(self, target: object, value: object, **kwargs: object) -> FmtExecutionResult:
        kwargs.setdefault("task_policy", FmtTaskPolicy.BY_ATOM)
        return self.base.write(target, value, **kwargs)

    def writes(self, writes: object, **kwargs: object) -> FmtExecutionResult:
        kwargs.setdefault("task_policy", FmtTaskPolicy.BY_ATOM)
        return self.base.writes(writes, **kwargs)

    def compare_write(
        self,
        target: object,
        value: object,
        **kwargs: object,
    ) -> FmtWriteComparison:
        kwargs.setdefault("task_policy", FmtTaskPolicy.BY_ATOM)
        return self.base.compare_write(target, value, **kwargs)

    def compare_writes(
        self,
        writes: object,
        **kwargs: object,
    ) -> FmtWritesComparison:
        kwargs.setdefault("task_policy", FmtTaskPolicy.BY_ATOM)
        return self.base.compare_writes(writes, **kwargs)

    def split_plan(
        self,
        plan: FmtWritePlan,
        *,
        task_policy: FmtTaskPolicy = FmtTaskPolicy.BY_ATOM,
        **kwargs: object,
    ) -> FmtWritePlan:
        return self.base.split_plan(plan, task_policy=task_policy, **kwargs)

    def execute_plan(self, plan: FmtWritePlan, **kwargs: object) -> FmtExecutionResult:
        if plan.task_policy != FmtTaskPolicy.BY_ATOM:
            plan = self.base.split_plan(plan, task_policy=FmtTaskPolicy.BY_ATOM)
        return self.base.execute_plan(plan, **kwargs)


__all__ = ["BlindFmtService"]
