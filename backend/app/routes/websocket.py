from fastapi import APIRouter, WebSocket, WebSocketDisconnect


router = APIRouter()

connected_clients = []


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    connected_clients.append(websocket)

    print(
        f"WebSocket client connected. "
        f"Total clients: {len(connected_clients)}"
    )

    try:

        while True:

            await websocket.receive_text()

    except WebSocketDisconnect:

        if websocket in connected_clients:
            connected_clients.remove(websocket)

        print(
            f"WebSocket client disconnected. "
            f"Total clients: {len(connected_clients)}"
        )


async def broadcast_alert(alert):

    disconnected_clients = []

    for client in connected_clients:

        try:

            await client.send_json({
                "type": "NEW_ALERT",
                "alert": alert
            })

        except Exception:

            disconnected_clients.append(client)


    for client in disconnected_clients:

        if client in connected_clients:
            connected_clients.remove(client)
