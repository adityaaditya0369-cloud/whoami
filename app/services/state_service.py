"""The only code path allowed to change Application.state."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.db import Application, MigrationEvent
from app.models.state import MigrationState, check_transition


def transition(session: Session, app: Application, target: MigrationState, actor: str,
               reason: str = "", detail: dict | None = None) -> MigrationEvent:
    current = MigrationState(app.state)
    check_transition(current, target, actor)
    app.state = target.value
    event = MigrationEvent(
        app_id=app.id, actor=actor, event_type="STATE_CHANGE",
        from_state=current.value, to_state=target.value,
        detail={"reason": reason, **(detail or {})},
    )
    session.add(event)
    return event


def record_event(session: Session, event_type: str, actor: str, app_id: str | None = None,
                 detail: dict | None = None) -> MigrationEvent:
    event = MigrationEvent(app_id=app_id, actor=actor, event_type=event_type, detail=detail or {})
    session.add(event)
    return event
