from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from bson import ObjectId
from fastapi import (
    APIRouter,
    HTTPException,
    Request,
    Depends
)
from app.services.alert_activity import record_alert_activity
from app.services.log_ingestion import parse_log_line
from app.detection.engine import run_detection_engine
from app.services.threat_summary import generate_threat_summary
from app.database import get_database
from app.utils.dependencies import get_current_user

router = APIRouter()


from pydantic import BaseModel, Field


class LogAnalysisRequest(BaseModel):
    logs: list[str] = Field(
        ...,
        min_length=1,
        max_length=5000
    )

class AlertStatusUpdate(BaseModel):
    status: str


def build_alert_fingerprint(alert):
    """
    Create a unique fingerprint for an alert.
    Used internally to prevent duplicate alerts.
    """

    alert_type = alert.get("alert_type")
    source_ip = alert.get("source_ip")

    if alert_type == "SSH Brute Force":

        return {
            "alert_type": alert_type,
            "source_ip": source_ip,
            "first_seen": alert.get("first_seen"),
            "last_seen": alert.get("last_seen"),
        }

    if alert_type == "Suspicious Login After Failed Attempts":

        return {
            "alert_type": alert_type,
            "source_ip": source_ip,
            "username": alert.get("username"),
            "timestamp": alert.get("timestamp"),
        }

    if alert_type == "Port Scan":

        return {
            "alert_type": alert_type,
            "source_ip": source_ip,
            "ports_scanned": alert.get("ports_scanned"),
            "timestamp": alert.get("timestamp"),
        }

    return {
        "alert_type": alert_type,
        "source_ip": source_ip,
    }


@router.post("/analyze")
async def analyze_logs(
    request: LogAnalysisRequest,
    http_request: Request,
    current_user: dict = Depends(get_current_user)
):
    total_size = sum(
        len(line.encode("utf-8"))
        for line in request.logs
    )

    if total_size > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Log payload cannot exceed 2 MB"
        )

    for line in request.logs:
        if len(line) > 10000:
            raise HTTPException(
                status_code=413,
                detail="A log line cannot exceed 10,000 characters"
            )
    events = []

    for line in request.logs:

        event = parse_log_line(
            line.strip()
        )

        if event:
            events.append(event)

    detected_alerts = run_detection_engine(
        events
    )

    db = get_database()

    new_alerts = []

    if db is not None:

        if events:

            await db.events.insert_many(
                events
            )

        for alert in detected_alerts:

            fingerprint = (
                build_alert_fingerprint(
                    alert
                )
            )

            existing_alert = (
                await db.alerts.find_one(
                    fingerprint
                )
            )

            if existing_alert:
                continue

            alert["detected_at"] = (
                datetime.now(timezone.utc)
            )

            alert["status"] = "DETECTED"

            alert["fingerprint"] = (
                fingerprint
            )

            new_alerts.append(alert)

        if new_alerts:

            result = (
                await db.alerts.insert_many(
                    new_alerts
                )
            )

            websocket_manager = (
                http_request
                .app
                .state
                .websocket_manager
            )

            for alert, alert_id in zip(
                new_alerts,
                result.inserted_ids
            ):

                alert["_id"] = str(
                    alert_id
                )

                await websocket_manager.broadcast(
                    {
                        "type": "NEW_ALERT",
                        "alert": alert
                    }
                )

                alert.pop(
                    "_id",
                    None
                )

        threat_summary = (
            generate_threat_summary(
                detected_alerts
            )
        )

    else:

        for alert in detected_alerts:

            alert["detected_at"] = (
                datetime.now(timezone.utc)
            )

            alert["status"] = "DETECTED"

        new_alerts = detected_alerts

        threat_summary = (
            generate_threat_summary(
                detected_alerts
            )
        )

    threat_summary["generated_at"] = (
        datetime.now(timezone.utc)
    )

    if db is not None:

        await db.threat_summaries.replace_one(
            {"_id": "latest"},
            {
                "_id": "latest",
                **threat_summary
            },
            upsert=True
        )

    for alert in new_alerts:

        alert.pop(
            "fingerprint",
            None
        )

    return {
        "events_processed": len(events),
        "alerts_detected": len(
            detected_alerts
        ),
        "new_alerts": len(
            new_alerts
        ),
        "alerts": new_alerts,
        "threat_summary": threat_summary
    }


@router.get("/alerts")
async def get_alerts(
    current_user: dict = Depends(get_current_user)
):

    db = get_database()

    if db is None:

        return {
            "alerts": [],
            "message": "Database not configured"
        }

    alerts = await db.alerts.find(
        {}
    ).sort(
        "_id",
        -1
    ).to_list(100)

    for alert in alerts:

        alert["_id"] = str(
            alert["_id"]
        )

        alert.pop(
            "fingerprint",
            None
        )

    return {
        "total": len(alerts),
        "alerts": alerts
    }
@router.patch("/alerts/{alert_id}")
async def update_alert_status(
    alert_id: str,
    request: AlertStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    db = get_database()

    if db is None:
        raise HTTPException(
            status_code=500,
            detail="Database not configured"
        )

    try:
        object_id = ObjectId(alert_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid alert ID"
        )

    alert = await db.alerts.find_one({
        "_id": object_id
    })

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    old_status = str(
    alert.get(
        "status",
        "DETECTED"
    )
).strip().upper()

    new_status = str(
    request.status
).strip().upper()
    valid_statuses = {
        "DETECTED",
        "INVESTIGATING",
        "RESOLVED"
    }

    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. "
                "Allowed values: DETECTED, "
                "INVESTIGATING, RESOLVED"
            )
        )

    if old_status == new_status:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Alert is already "
                f"{new_status}"
            )
        )

    valid_transitions = {
        "DETECTED": {
            "INVESTIGATING"
        },
        "INVESTIGATING": {
            "RESOLVED"
        },
        "RESOLVED": {
            "INVESTIGATING"
        }
    }

    allowed_next_states = valid_transitions.get(
        old_status,
        set()
    )

    if new_status not in allowed_next_states:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid status transition: "
                f"{old_status} → {new_status}"
            )
        )

    result = await db.alerts.update_one(
        {
            "_id": object_id,
            "status": old_status
        },
        {
            "$set": {
                "status": new_status
            }
        }
    )

    if result.modified_count == 0:
        raise HTTPException(
            status_code=409,
            detail=(
                "Alert status changed before "
                "this update could be applied"
            )
        )

    await record_alert_activity(
        db=db,
        alert_id=object_id,
        action=(
            f"Status changed from "
            f"{old_status} to "
            f"{new_status}"
        ),
        username=current_user.get(
            "username",
            "unknown"
        )
    )

    updated_alert = await db.alerts.find_one({
        "_id": object_id
    })

    if updated_alert:
        updated_alert["_id"] = str(
            updated_alert["_id"]
        )

    return {
        "message": "Alert status updated",
        "alert": updated_alert
    }


@router.get("/alerts/{alert_id}/activity")
async def get_alert_activity(
    alert_id: str,
    current_user: dict = Depends(get_current_user)
):

    db = get_database()

    if db is None:

        raise HTTPException(
            status_code=500,
            detail="Database not configured"
        )

    try:

        object_id = ObjectId(
            alert_id
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert ID"
        )

    alert = await db.alerts.find_one(
        {
            "_id": object_id
        }
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    activity = await db.alert_activity.find(
        {
            "alert_id": alert_id
        },
        {
            "_id": 0
        }
    ).sort(
        "timestamp",
        -1
    ).to_list(100)

    return {
        "alert_id": alert_id,
        "total": len(activity),
        "activity": activity
    }
class AlertNoteRequest(BaseModel):
    note: str


@router.post("/alerts/{alert_id}/notes")
async def add_alert_note(
    alert_id: str,
    request: AlertNoteRequest,
    current_user: dict = Depends(
        get_current_user
    )
):

    db = get_database()

    if db is None:
        raise HTTPException(
            status_code=500,
            detail="Database not configured"
        )

    try:
        object_id = ObjectId(
            alert_id
        )

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid alert ID"
        )

    alert = await db.alerts.find_one(
        {
            "_id": object_id
        }
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    note = request.note.strip()

    if not note:
        raise HTTPException(
            status_code=400,
            detail="Note cannot be empty"
        )

    if len(note) > 1000:
        raise HTTPException(
            status_code=400,
            detail="Note cannot exceed 1000 characters"
        )

    username = current_user.get(
        "username",
        "unknown"
    )

    activity = await record_alert_activity(
        db=db,
        alert_id=object_id,
        action="Analyst added investigation note",
        username=username,
        note=note
    )

    activity.pop(
        "_id",
        None
    )

    return {
        "message": "Investigation note added",
        "activity": activity
    }
@router.get("/events")
async def get_events(
     current_user: dict = Depends(get_current_user)
):

    db = get_database()

    if db is None:

        return {
            "events": [],
            "message": "Database not configured"
        }

    events = await db.events.find(
        {},
        {
            "_id": 0
        }
    ).sort(
        "timestamp",
        -1
    ).to_list(50)

    return {
        "total": len(events),
        "events": events
    }


@router.get("/stats")
async def get_stats(
    current_user: dict = Depends(get_current_user)
):

    db = get_database()

    if db is None:

        return {
            "total_alerts": 0,
            "active_alerts": 0,
            "investigating": 0,
            "resolved": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "total_events": 0
        }

    total_alerts = await db.alerts.count_documents({})

    active_alerts = await db.alerts.count_documents({
        "status": "DETECTED"
    })

    investigating = await db.alerts.count_documents({
        "status": "INVESTIGATING"
    })

    resolved = await db.alerts.count_documents({
        "status": "RESOLVED"
    })

    high_severity = await db.alerts.count_documents({
        "severity": "HIGH"
    })

    medium_severity = await db.alerts.count_documents({
        "severity": "MEDIUM"
    })

    total_events = await db.events.count_documents({})

    return {
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "investigating": investigating,
        "resolved": resolved,
        "high_severity": high_severity,
        "medium_severity": medium_severity,
        "total_events": total_events
    }


@router.get("/threat-summary")
async def get_threat_summary(
    current_user: dict = Depends(get_current_user)
):

    db = get_database()

    if db is None:

        return {
            "threat_summary": None,
            "message": "Database not configured"
        }

    summary = await db.threat_summaries.find_one(
        {
            "_id": "latest"
        },
        {
            "_id": 0
        }
    )

    return {
        "threat_summary": summary
    }
