from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings
from app.models import TokenRequest, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

FAKE_USER_DB = {
    "admin": {
        "username": "admin",
        "role": "security_admin",
        "disabled": False,
        "hashed_password": pwd_context.hash("AdminPass123!"),
    },
    "analyst": {
        "username": "analyst",
        "role": "security_analyst",
        "disabled": False,
        "hashed_password": pwd_context.hash("AnalystPass123!"),
    },
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(form: TokenRequest) -> User | None:
    user_record = FAKE_USER_DB.get(form.username)
    if not user_record:
        return None
    if not verify_password(form.password, user_record["hashed_password"]):
        return None
    return User(
        username=user_record["username"],
        role=user_record["role"],
        disabled=user_record["disabled"],
    )


def create_access_token( dict, expires_minutes: int | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> User:
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_record = FAKE_USER_DB.get(username)
    if not user_record or user_record["disabled"]:
        raise credentials_exception

    return User(
        username=user_record["username"],
        role=user_record["role"],
        disabled=user_record["disabled"],
    )
