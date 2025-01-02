from hmac import new
from typing import Annotated, Optional
import fastapi

from ..auth import User, get_current_active_user
from ..db import db
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel
from ..error import error

router = fastapi.APIRouter(prefix="/leaderboard")


class LeaderboardItem(BaseModel):
    name: str
    points: Optional[int]


class EditLeaderboardItem(BaseModel):
    name: Optional[str]
    points: Optional[int]


@router.get("/list", response_class=ORJSONResponse, status_code=200)
async def get(name: Optional[str] = None):
    async with db.acquire() as conn:
        
        if name is not None:
            wildcard = f"%{name}%"
            result = await conn.fetch("""
                SELECT name, points
                FROM leaderboard
                WHERE lower(name) ILIKE LOWER($1)
                OR name % '$2'
                ORDER BY similarity(lower(name), lower($2)) DESC;
            """, wildcard, name)
            return result
        
        result = await conn.fetch(
            "SELECT name, points FROM leaderboard ORDER BY points DESC;"
        )
        return result


@router.post("/create", response_class=ORJSONResponse, status_code=201)
async def post(
    current_user: Annotated[User, fastapi.Depends(get_current_active_user)],
    item: LeaderboardItem,
):
    async with db.acquire() as conn:
        result = await conn.fetchval(
            """
                    WITH ins AS (
                        INSERT INTO leaderboard (name, points)
                        VALUES ($1, $2)
                        ON CONFLICT (name) DO NOTHING
                        RETURNING 1
                    )
                    SELECT COALESCE((SELECT 1 FROM ins), NULL) AS result;
                """,
            item.name,
            item.points,
        )
        if result == None:
            raise error(409, "resource already exist")
        return item


@router.patch("/{username}", response_class=ORJSONResponse, status_code=200)
async def patch(
    current_user: Annotated[User, fastapi.Depends(get_current_active_user)],
    username: str,
    new_data: EditLeaderboardItem,
):
    async with db.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT name, points FROM leaderboard WHERE LOWER(name) = LOWER($1)", username
        )

        if user is None:
            return error(404, "resource does not exist")

        user = LeaderboardItem(name=user["name"], points=user["points"])
        new_data.name = new_data.name or user.name
        new_data.points = new_data.points or user.points
        await conn.execute(
            "UPDATE leaderboard SET name = $1, points = $2 WHERE LOWER(name) = LOWER($3)",
            new_data.name,
            new_data.points,
            user.name,
        )
        return new_data


@router.get(
    "/{username}",
    response_class=ORJSONResponse,
    status_code=200,
    response_model=LeaderboardItem,
)
async def get_user(username: str):
    async with db.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT name, points FROM leaderboard WHERE LOWER(name) = LOWER($1)", username
        )
        if user is None:
            raise error(404, "resource does not exist")
        return dict(user)
