import traceback
import jwt
from typing import Annotated, Any, Literal, Optional
from asyncpg import Connection, Record
from asyncpg.pool import PoolConnectionProxy
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from os import getenv
from datetime import timedelta, datetime, timezone
from pydantic import BaseModel
from .db import db
from .error import error


SECRET_KEY = getenv("SECRET_KEY")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 900
REFRESH_TOKEN_EXPIRE_SECONDS = 1209600

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

pwd_ctx = CryptContext(schemes=["bcrypt"])


class AccessToken(BaseModel):
    token: str
    token_type: str
    expires_in: int
    expires_at: int


class RefreshToken(BaseModel):
    token: str
    expires_in: int
    expires_at: int


class Token(BaseModel):
    access_token: AccessToken
    refresh_token: RefreshToken


class TokenData(BaseModel):
    user_id: int | None = None


class User(BaseModel):
    id: int
    name: str


class RealUser(User):
    password: str


class SessionUser(RealUser):
    access_token: str


def verify_password(password: str, hashed_password: str):
    return pwd_ctx.verify(password, hashed_password)


def get_password_hash(password: str):
    return pwd_ctx.hash(password)


async def fetch_user(conn: Connection | PoolConnectionProxy, id: int):
    user: Record | None = await conn.fetchrow(
        "SELECT id, name, password FROM admin WHERE id = $1", id
    )
    if user is not None:
        return RealUser(**user)


async def authenticate_user(
    conn: Connection | PoolConnectionProxy, name: str, password: str
):
    user: Record | None = await conn.fetchrow(
        "SELECT id, name, password FROM admin WHERE name = $1", name
    )
    if user is None or not verify_password(password, user["password"]):
        return False
    return RealUser(**user)


def create_access_token(data: dict):
    to_encode = data.copy()

    expires_in_seconds = timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    expire = datetime.now(timezone.utc) + expires_in_seconds

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt, expires_in_seconds, expire


def create_refresh_token(user_id: int):
    to_encode: dict[str, Any] = {"sub": str(user_id)}

    expires_in_seconds = timedelta(seconds=259200)
    expire = datetime.now(timezone.utc) + expires_in_seconds

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt, expires_in_seconds, expire


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = error(401, "Could not validate credentials")

    async with db.acquire() as conn:

        token_is_valid = await conn.fetchval(
            "SELECT 1 FROM access_tokens WHERE token = $1", token
        )

        if token_is_valid != 1:
            raise credentials_exception

        try:
            payload: dict[str, str] = jwt.decode(
                token, SECRET_KEY, algorithms=[JWT_ALGORITHM]
            )
            id: str | None = payload.get("sub")
            if id is None:
                raise credentials_exception

        except jwt.InvalidTokenError as e:
            traceback.print_exception(e)
            raise credentials_exception

        token_data = TokenData()
        token_data.user_id = int(id)

        user = await fetch_user(conn, id=token_data.user_id)
        if user is None:
            raise credentials_exception
        return SessionUser(**dict(user), access_token=token)


async def get_current_active_user(
    current_user: Annotated[SessionUser, Depends(get_current_user)],
):
    return current_user


async def invalidate_token(conn: Connection | PoolConnectionProxy, token: str):
    ret: Literal[1] | None = await conn.fetchval(
        """
            DELETE FROM access_tokens
            WHERE token = $1
            RETURNING 1;
        """,
        token,
    )
    if ret == 1:
        return True
    return ret


async def refresh_user_token(access_token: str, refresh_token: str, device_id: Optional[str] = None):

    async with db.acquire() as conn:
        async with conn.transaction():

            user_id: int | None = await conn.fetchval(
                "SELECT access_tokens.user FROM access_tokens WHERE refresh_token = $1 AND token = $2",
                refresh_token,
                access_token,
            )

            if user_id is None:
                return None

            try:
                payload: dict[str, str] = jwt.decode(
                    refresh_token, SECRET_KEY, algorithms=[JWT_ALGORITHM]
                )
                id: str | None = payload.get("sub")
                if id is None:
                    return None

            except jwt.ExpiredSignatureError:
                await conn.execute(
                    "DELETE FROM access_tokens WHERE refresh_token = $1", refresh_token
                )
                return False

            except jwt.InvalidTokenError as e:
                traceback.print_exception(e)
                return None

            new_access_token = create_access_token({"sub": str(user_id)})
            new_refresh_token = create_refresh_token(user_id)
            
            await conn.execute(
                "UPDATE access_tokens SET token = $1, refresh_token = $2, device_id = $3  WHERE token = $4", new_access_token[0], new_refresh_token[0], device_id, access_token
            )

            return Token(
                access_token=AccessToken(
                    token=new_access_token[0],
                    token_type="bearer",
                    expires_in=int(new_access_token[1].total_seconds()),
                    expires_at=int(new_access_token[2].timestamp()),
                ),
                refresh_token=RefreshToken(
                    token=new_refresh_token[0],
                    expires_in=int(new_refresh_token[1].total_seconds()),
                    expires_at=int(new_refresh_token[2].timestamp()),
                ),
            )
