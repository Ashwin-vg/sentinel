from datetime import datetime, timezone


async def record_alert_activity(
    db,
    alert_id,
    action,
    username,
    note=None
):
    activity = {
        "alert_id": str(alert_id),
        "action": action,
        "username": username,
        "note": note,
        "timestamp": datetime.now(timezone.utc)
    }

    await db.alert_activity.insert_one(
        activity
    )

    return activity
