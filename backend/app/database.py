import os

from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv


load_dotenv()


MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "sentinel")


if not MONGODB_URL:
    raise RuntimeError(
        "MONGODB_URL is not configured in environment variables"
    )


client = AsyncIOMotorClient(
    MONGODB_URL,
    serverSelectionTimeoutMS=5000
)

db = client[DATABASE_NAME]


def get_database():
    return db