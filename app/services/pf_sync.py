"""Read PingFederate (read-only) and store SP connections / OAuth clients."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.integrations.pingfederate import parser as pfp
from app.integrations.pingfederate.client import PfSource
from app.models.db import PfObject, PfSyncRun
from app.services.state_service import record_event

log = logging.getLogger(__name__)


def run_pf_sync(session: Session, source: PfSource, settings: Settings, actor: str = "system") -> PfSyncRun:
    run = PfSyncRun(source=settings.pf_source.value, source_ref=source.describe(), actor=actor)
    session.add(run)
    session.flush()
    try:
        parsed = [(r, pfp.parse_sp_connection(r)) for r in source.list_sp_connections()]
        parsed += [(r, pfp.parse_oauth_client(r)) for r in source.list_oauth_clients()]
        existing = {(o.kind, o.pf_id): o for o in session.scalars(select(PfObject))}
        seen = set()
        for raw, m in parsed:
            k = (m.kind, m.pf_id)
            seen.add(k)
            row = existing.get(k) or PfObject(kind=m.kind, pf_id=m.pf_id)
            row.key, row.name, row.active = m.key, m.name, m.active
            row.details = m.model_dump(exclude={"kind", "pf_id", "key", "name", "active"})
            row.raw, row.last_sync_id, row.removed = raw, run.id, False
            session.add(row)
            if m.kind == "SP_CONNECTION":
                run.sp_connections += 1
            else:
                run.oauth_clients += 1
        for k, row in existing.items():
            if k not in seen:
                row.removed = True
        run.status = "SUCCESS"
        record_event(session, "PF_SYNC_COMPLETED", actor, detail={
            "run_id": run.id, "sp_connections": run.sp_connections, "oauth_clients": run.oauth_clients})
        session.commit()
    except Exception as exc:
        session.rollback()
        run = session.get(PfSyncRun, run.id) or run
        run.status, run.error = "FAILED", f"{type(exc).__name__}: {exc}"[:2000]
        session.add(run)
        record_event(session, "PF_SYNC_FAILED", actor, detail={"error": run.error})
        session.commit()
        log.exception("PingFederate sync failed")
        raise
    return run
