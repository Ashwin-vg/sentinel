from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database import get_database
from app.utils.auth import (
    hash_password,
    verify_password,
    create_access_token
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
async def register_user(request: RegisterRequest):

    db = get_database()

    if db is None:
        raise HTTPException(
            status_code=500,
            detail="Database not configured"
        )

    username = request.username.strip()

    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must contain at least 3 characters"
        )

    if len(request.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 6 characters"
        )

    existing_user = await db.users.find_one({
        "username": username
    })

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    user = {
        "username": username,
        "password": hash_password(request.password),
        "role": "analyst"
    }

    result = await db.users.insert_one(user)

    return {
        "message": "User registered successfully",
        "user_id": str(result.inserted_id),
        "username": username,
        "role": "analyst"
    }


@router.post("/login")
async def login_user(request: LoginRequest):

    db = get_database()

    if db is None:
        raise HTTPException(
            status_code=500,
            detail="Database not configured"
        )

    username = request.username.strip()

    user = await db.users.find_one({
        "username": username
    })

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    password_valid = verify_password(
        request.password,
        user["password"]
    )

    if not password_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    access_token = create_access_token({
        "sub": str(user["_id"]),
        "username": user["username"],
        "role": user.get("role", "analyst")
    })

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "role": user.get("role", "analyst")
        }
    }
