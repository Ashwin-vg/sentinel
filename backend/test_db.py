import asyncio

from app.database import client


async def main():
    result = await client.admin.command("ping")
    print(result)


asyncio.run(main())
