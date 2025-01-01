from contextlib import asynccontextmanager
import os
import asyncpg
from fastapi import FastAPI

db = asyncpg.create_pool(os.getenv("DATABASE_URL"), min_size=1, max_size=10)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with db:
        yield
