from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from datetime import datetime
from bson import ObjectId

from app.services.log_ingestion import parse_log_line
from app.detection.engine import run_detection_engine
from app.services.threat_summary import generate_threat_summary
from app.database import get_database


router = APIRouter()


class LogAnalysisRequest(BaseModel):

    logs: list[str]


class AlertStatusUpdate(BaseModel):

    status: str


# ============================================================
# ANALYZE LOGS
# ============================================================

@router.post("/analyze")
async def analyze_logs(
    request: LogAnalysisRequest,
    http_request: Request
):

    events = []


    # --------------------------------------------------------
    # Parse logs
    # --------------------------------------------------------

    for line in request.logs:

        event = parse_log_line(
            line.strip()
        )

        if event:

            events.append(
                event
            )


    # --------------------------------------------------------
    # Detection engine
    # --------------------------------------------------------

    alerts = run_detection_engine(
        events
    )


    # --------------------------------------------------------
    # Threat summary
    # --------------------------------------------------------

    threat_summary = generate_threat_summary(
        alerts
    )


    threat_summary["generated_at"] = datetime.utcnow()


    # --------------------------------------------------------
    # Prepare alerts
    # --------------------------------------------------------

    for alert in alerts:

        alert["detected_at"] = datetime.utcnow()

        alert["status"] = "DETECTED"


    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    db = get_database()


    if db is not None:

        # Store events

        if events:

            await db.events.insert_many(
                events
            )


        # Store alerts

        if alerts:

            result = await db.alerts.insert_many(
                alerts
            )


            for alert, alert_id in zip(
                alerts,
                result.inserted_ids
            ):

                alert["_id"] = str(
                    alert_id
                )


            # ------------------------------------------------
            # REAL-TIME WEBSOCKET BROADCAST
            # ------------------------------------------------

            websocket_manager = (
                http_request
                .app
                .state
                .websocket_manager
            )


            for alert in alerts:

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


        # Store latest threat summary

        await db.threat_summaries.replace_one(
            {
                "_id": "latest"
            },
            {
                "_id": "latest",
                **threat_summary
            },
            upsert=True
        )


    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {

        "events_processed":
            len(events),

        "alerts_detected":
            len(alerts),

        "alerts":
            alerts,

        "threat_summary":
            threat_summary

    }


# ============================================================
# GET ALERTS
# ============================================================

@router.get("/alerts")
async def get_alerts():

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


    return {

        "total":
            len(alerts),

        "alerts":
            alerts

    }


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

@router.patch("/alerts/{alert_id}")
async def update_alert_status(
    alert_id: str,
    request: AlertStatusUpdate
):

    allowed_statuses = [
        "DETECTED",
        "INVESTIGATING",
        "RESOLVED"
    ]


    if request.status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert status"
        )


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


    result = await db.alerts.update_one(
        {
            "_id": object_id
        },
        {
            "$set": {
                "status":
                    request.status,

                "updated_at":
                    datetime.utcnow()
            }
        }
    )


    if result.matched_count == 0:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )


    updated_alert = await db.alerts.find_one(
        {
            "_id": object_id
        }
    )


    if updated_alert:

        updated_alert["_id"] = str(
            updated_alert["_id"]
        )


    return {

        "message":
            "Alert status updated",

        "alert":
            updated_alert

    }


# ============================================================
# GET EVENTS
# ============================================================

@router.get("/events")
async def get_events():

    db = get_database()


    if db is None:

        return {

            "events": [],

            "message":
                "Database not configured"

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

        "total":
            len(events),

        "events":
            events

    }


# ============================================================
# GET STATS
# ============================================================

@router.get("/stats")
async def get_stats():

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


    total_alerts = await db.alerts.count_documents(
        {}
    )


    active_alerts = await db.alerts.count_documents(
        {
            "status": "DETECTED"
        }
    )


    investigating = await db.alerts.count_documents(
        {
            "status": "INVESTIGATING"
        }
    )


    resolved = await db.alerts.count_documents(
        {
            "status": "RESOLVED"
        }
    )


    high_severity = await db.alerts.count_documents(
        {
            "severity": "HIGH"
        }
    )


    medium_severity = await db.alerts.count_documents(
        {
            "severity": "MEDIUM"
        }
    )


    total_events = await db.events.count_documents(
        {}
    )


    return {

        "total_alerts":
            total_alerts,

        "active_alerts":
            active_alerts,

        "investigating":
            investigating,

        "resolved":
            resolved,

        "high_severity":
            high_severity,

        "medium_severity":
            medium_severity,

        "total_events":
            total_events

    }


# ============================================================
# THREAT SUMMARY
# ============================================================

@router.get("/threat-summary")
async def get_threat_summary():

    db = get_database()


    if db is None:

        return {

            "threat_summary":
                None,

            "message":
                "Database not configured"

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

        "threat_summary":
            summary

    }
