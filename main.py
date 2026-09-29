
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="DEVHUB API",
    description="Backend for the DEVHUB chat application",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "status": "online",
        "app": "DEVHUB",
        "message": "DEVHUB backend is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
