import fastapi
import os
from .db import lifespan
from .routes import leaderboard, auth
from fastapi.middleware.cors import CORSMiddleware

app = fastapi.FastAPI(
    debug=os.getenv("ENVIRONMENT", "development").lower() == "development",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(leaderboard.router)
app.include_router(auth.router)
