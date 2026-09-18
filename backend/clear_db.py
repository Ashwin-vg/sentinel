import asyncio

from app.database import db


async def main():

    if db is None:
        print("Database not configured")
        return

    alerts_result = await db.alerts.delete_many({})
    events_result = await db.events.delete_many({})

    print(f"Deleted alerts: {alerts_result.deleted_count}")
    print(f"Deleted events: {events_result.deleted_count}")


asyncio.run(main())
