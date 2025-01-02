from typing import Annotated
from fastapi import APIRouter, Depends, Form
from fastapi.security import OAuth2PasswordRequestForm
from ..error import error
from ..db import db
from ..auth import (
    SessionUser,
    Token,
    RefreshToken,
    AccessToken,
    User,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    get_current_active_user,
    invalidate_token,
    refresh_user_token,
)

router = APIRouter(prefix="/auth")


@router.post("/token", status_code=201)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    async with db.acquire() as conn:
        user = await authenticate_user(conn, form_data.username, form_data.password)
        if not user:
            raise error(401, "Incorrect username or password")
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(user.id)
        token = Token(
            access_token=AccessToken(
                token=access_token[0],
                token_type="bearer",
                expires_in=int(access_token[1].total_seconds()),
                expires_at=int(access_token[2].timestamp()),
            ),
            refresh_token=RefreshToken(
                token=refresh_token[0],
                expires_in=int(refresh_token[1].total_seconds()),
                expires_at=int(refresh_token[2].timestamp()),
            ),
        )

        await conn.execute(
            'INSERT INTO access_tokens (token, "user", refresh_token) VALUES ($1, $2, $3);',
            token.access_token.token,
            user.id,
            token.refresh_token.token,
        )
        return token


@router.post("/token/invalidate", status_code=204)
async def invalidate_user_token(
    current_user: Annotated[SessionUser, Depends(get_current_active_user)]
):
    async with db.acquire() as conn:
        ret = await invalidate_token(conn, current_user.access_token)
        return


@router.post("/token/refresh", status_code=200)
async def _refresh_user_token(
    access_token: Annotated[str, Form()], refresh_token: Annotated[str, Form()]
) -> Token:
    token = await refresh_user_token(
        access_token=access_token, refresh_token=refresh_token
    )
    if token is False or token is None:
        raise error(401, "invalid credentials")
    return token


@router.get("/me/", response_model=User, status_code=200)
async def read_users_me(
    current_user: Annotated[SessionUser, Depends(get_current_active_user)],
):
    return User(**dict(current_user))
