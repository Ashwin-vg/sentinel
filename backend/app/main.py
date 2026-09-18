from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.routes.analyze import router as analyze_router
from app.routes.auth import router as auth_router


app = FastAPI(
    title="Sentinel",
    description="Security Operations & Threat Detection Platform",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# WEBSOCKET CONNECTION MANAGER
# ============================================================

class ConnectionManager:

    def __init__(self):

        self.active_connections = []


    async def connect(
        self,
        websocket: WebSocket
    ):

        await websocket.accept()

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


# Global WebSocket manager

manager = ConnectionManager()


# ============================================================
# WEBSOCKET ENDPOINT
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket
):

    await manager.connect(
        websocket
    )


    try:

        while True:

            await websocket.receive_text()


    except WebSocketDisconnect:

        manager.disconnect(
            websocket
        )

    except Exception:

        manager.disconnect(
            websocket
        )


# Make manager accessible to other modules

app.state.websocket_manager = manager


# ============================================================
# API ROUTES
# ============================================================

app.include_router(
    analyze_router,
    prefix="/api",
    tags=["Security Analysis"]
)


app.include_router(
    auth_router,
    prefix="/api"
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "name": "Sentinel",
        "status": "online",
        "version": "1.0.0"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }
