from fastapi import FastAPI

app = FastAPI(
    title="Sentinel",
    description="Security Operations & Threat Detection Platform",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "name": "Sentinel",
        "status": "online",
        "version": "1.0.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
