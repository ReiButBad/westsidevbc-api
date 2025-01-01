from fastapi import HTTPException


def error(
    status_code: int, message: str, headers: dict[str, str] | None = None, **details
):
    return HTTPException(
        status_code=status_code, detail={"message": message, **details}, headers=headers
    )
