import asyncio
import json
import time

from collections import defaultdict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routes.analyze import router as analyze_router
from app.routes.auth import router as auth_router
from app.utils.auth import decode_access_token


app = FastAPI(
    title="Sentinel",
    description="Security Operations & Threat Detection Platform",
    version="1.0.0"
)


# ==========================================================
# RATE LIMITING
# ==========================================================

rate_limit_store = defaultdict(list)

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_REQUESTS = 120


def check_rate_limit(client_ip: str):

    current_time = time.time()

    request_times = rate_limit_store[client_ip]

    request_times[:] = [
        timestamp
        for timestamp in request_times
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]

    if len(request_times) >= RATE_LIMIT_REQUESTS:
        return False

    request_times.append(current_time)

    return True


# ==========================================================
# RATE LIMIT MIDDLEWARE
# ==========================================================

@app.middleware("http")
async def rate_limit_middleware(
    request,
    call_next
):

    # Allow browser CORS preflight requests
    if request.method == "OPTIONS":
        return await call_next(request)

    client_ip = request.client.host

    if not check_rate_limit(client_ip):

        return JSONResponse(
            status_code=429,
            content={
                "detail": (
                    "Too many requests. "
                    "Please try again later."
                )
            }
        )

    response = await call_next(request)

    return response


# ==========================================================
# CORS
# ==========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://ashwin-vg.github.io"
    ],

    allow_credentials=True,

    allow_methods=[
        "GET",
        "POST",
        "PATCH",
        "OPTIONS"
    ],

    allow_headers=[
        "Authorization",
        "Content-Type"
    ],
)


# ==========================================================
# WEBSOCKET CONNECTION MANAGER
# ==========================================================

class ConnectionManager:

    def __init__(self):

        self.active_connections = []


    async def connect(
        self,
        websocket: WebSocket
    ):

        self.active_connections.append(
            websocket
        )


    def disconnect(
        self,
        websocket: WebSocket
    ):

        if websocket in self.active_connections:

            self.active_connections.remove(
                websocket
            )


    async def broadcast(
        self,
        message: dict
    ):

        disconnected = []

        for connection in self.active_connections:

            try:

                await connection.send_json(
                    message
                )

            except Exception:

                disconnected.append(
                    connection
                )

        for connection in disconnected:

            self.disconnect(
                connection
            )


manager = ConnectionManager()


# ==========================================================
# WEBSOCKET
# ==========================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket
):

    await websocket.accept()

    try:

        # --------------------------------------------------
        # WAIT FOR JWT AUTHENTICATION
        # --------------------------------------------------

        auth_message = await asyncio.wait_for(
            websocket.receive_text(),
            timeout=5
        )


        try:

            data = json.loads(
                auth_message
            )

        except json.JSONDecodeError:

            await websocket.close(
                code=1008,
                reason="Invalid authentication message"
            )

            return


        if data.get("type") != "AUTH":

            await websocket.close(
                code=1008,
                reason="Authentication required"
            )

            return


        token = data.get("token")


        if not token:

            await websocket.close(
                code=1008,
                reason="JWT token missing"
            )

            return


        # --------------------------------------------------
        # VALIDATE JWT
        # --------------------------------------------------

        payload = decode_access_token(
            token
        )


        if not payload:

            await websocket.close(
                code=1008,
                reason="Invalid or expired token"
            )

            return


        # --------------------------------------------------
        # AUTHENTICATED CONNECTION
        # --------------------------------------------------

        await manager.connect(
            websocket
        )


        username = payload.get(
            "username",
            "unknown"
        )


        await websocket.send_json({

            "type": "AUTHENTICATED",

            "username": username

        })


        print(
            f"WebSocket authenticated: {username}"
        )


        # --------------------------------------------------
        # KEEP CONNECTION ALIVE
        # --------------------------------------------------

        while True:

            await websocket.receive_text()


    except asyncio.TimeoutError:

        await websocket.close(
            code=1008,
            reason="Authentication timeout"
        )


    except WebSocketDisconnect:

        manager.disconnect(
            websocket
        )

        print(
            "WebSocket disconnected"
        )


    except Exception as error:

        manager.disconnect(
            websocket
        )

        print(
            f"WebSocket error: {error}"
        )


# ==========================================================
# APPLICATION STATE
# ==========================================================

app.state.websocket_manager = manager


# ==========================================================
# ROUTES
# ==========================================================

app.include_router(
    analyze_router,
    prefix="/api",
    tags=["Security Analysis"]
)


app.include_router(
    auth_router,
    prefix="/api"
)


# ==========================================================
# ROOT
# ==========================================================

@app.get("/")
def root():

    return {

        "name": "Sentinel",

        "status": "online",

        "version": "1.0.0"

    }


# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.get("/health")
def health():

    return {

        "status": "healthy"

    }