from pwdlib import PasswordHash
import jwt
from datetime import timedelta, UTC, datetime
from typing import Optional
from settings import settings 

password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("anydummy")
ACCESS_TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10
REFRESH_TOKEN_EXPIRE_DAYS = 7
REFRESH_TOKEN_ALGORITHM = "HS256"


#password generation
def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)

# ---- JWT Generation + Encoding/Decoding
def create_access_token(data: dict, experis_delta: timedelta | None = None) -> str:
    if experis_delta:
        expiration_time = datetime.now(UTC) + experis_delta
    else:
        now = datetime.now(UTC)
        expiration_time = now + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {**data, "iat": int(now.timestamp()), "exp": expiration_time, "type": "access"}


    encoded_jwt = jwt.encode(
        to_encode,
        key=settings.JWT_SECRET_KEY,
        algorithm=ACCESS_TOKEN_ALGORITHM
    )
    return encoded_jwt

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            key=settings.JWT_SECRET_KEY,
            algorithms=[ACCESS_TOKEN_ALGORITHM]
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError("Invalid token")


# Refresh token
def create_refresh_token(data: dict, experis_delta: timedelta | None = None) -> str:
    if experis_delta:
        expiration_time = datetime.now(UTC) + experis_delta
    else:
        now = datetime.now(UTC)
        expiration_time = now + timedelta(days = REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {**data, "iat": int(now.timestamp()), "exp": expiration_time, "type": "refresh"}

    encoded_jwt = jwt.encode(
        to_encode,
        key=settings.JWT_SECRET_KEY,
        algorithm=ACCESS_TOKEN_ALGORITHM
    )
    return encoded_jwt