import hashlib
import secrets
import hmac

from datetime import datetime, timedelta, timezone

from fastapi import Request, Response, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database import get_db
from config import settings
from app.models.models import User, UserSession


# =========================
# PASSWORD HASHING
# =========================

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


# =========================
# SESSION CONFIGURATION
# =========================

SESSION_COOKIE = "greenroots_session"
SESSION_DURATION = 3600


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# =========================
# CREATE SESSION
# =========================

def create_session(
    response: Response,
    user: User,
    db: Session
):
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)

    new_session = UserSession(
        user_id=user.id,
        token_hash=hash_token(session_token),
        csrf_token=csrf_token,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=SESSION_DURATION)
    )

    db.add(new_session)
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        max_age=SESSION_DURATION,
        httponly=True,
        secure=settings.SESSION_HTTPS_ONLY,
        samesite="lax",
        path="/"
    )

    return csrf_token


# =========================
# GET CURRENT SESSION
# =========================

def get_session(
    request: Request,
    db: Session
):
    token = request.cookies.get(SESSION_COOKIE)

    if not token:
        return None

    token_hash = hash_token(token)

    return db.scalar(
        select(UserSession).where(
            UserSession.token_hash == token_hash,
            UserSession.expires_at > datetime.now(timezone.utc)
        )
    )


# =========================
# AUTHENTICATION
# =========================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    session = get_session(request, db)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Silakan login terlebih dahulu"
        )

    user = db.get(User, session.user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Akun tidak aktif atau tidak ditemukan"
        )

    request.state.csrf_token = session.csrf_token

    return user


# =========================
# AUTHORIZATION
# =========================

def require_admin(
    user: User = Depends(get_current_user)
):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses hanya untuk administrator"
        )

    return user


# =========================
# CSRF PROTECTION
# =========================

def verify_csrf(
    request: Request,
    submitted_token: str,
    db: Session
):
    session = get_session(request, db)

    if not session or not submitted_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token tidak valid"
        )

    if not hmac.compare_digest(
        session.csrf_token,
        submitted_token
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permintaan ditolak"
        )

    return True


# =========================
# LOGOUT
# =========================

def destroy_session(
    request: Request,
    response: Response,
    db: Session
):
    session = get_session(request, db)

    if session:
        db.delete(session)
        db.commit()

    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=settings.SESSION_HTTPS_ONLY,
        samesite="lax"
    )

# =========================
# ANONYMOUS CSRF
# =========================

CSRF_COOKIE = "greenroots_csrf"


def create_anonymous_csrf(response: Response):
    nonce = secrets.token_urlsafe(32)

    signature = hmac.new(
        settings.SECRET_KEY.encode(),
        nonce.encode(),
        hashlib.sha256
    ).hexdigest()

    token = f"{nonce}.{signature}"

    response.set_cookie(
        key=CSRF_COOKIE,
        value=nonce,
        httponly=True,
        secure=settings.SESSION_HTTPS_ONLY,
        samesite="lax",
        path="/",
        max_age=3600
    )

    return token


def verify_anonymous_csrf(
    request: Request,
    submitted_token: str
):
    nonce = request.cookies.get(CSRF_COOKIE)

    if not nonce:
        raise HTTPException(
            status_code=403,
            detail="Cookie CSRF tidak ditemukan. Silakan muat ulang halaman login."
        )

    if not submitted_token:
        raise HTTPException(
            status_code=403,
            detail="Form CSRF token tidak ditemukan."
        )

    expected_signature = hmac.new(
        settings.SECRET_KEY.encode(),
        nonce.encode(),
        hashlib.sha256
    ).hexdigest()

    expected_token = f"{nonce}.{expected_signature}"

    if not hmac.compare_digest(expected_token, submitted_token):
        raise HTTPException(
            status_code=403,
            detail="CSRF token tidak valid. Silakan muat ulang halaman login."
        )

    return True