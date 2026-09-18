import os

from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv


load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "sentinel")

client = None
db = None


if MONGODB_URL:
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]


def get_database():
    return db
