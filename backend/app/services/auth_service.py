from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import verify_password, decode_access_token
from app.models.user import User, UserRole
from app.core.logger import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

async def authenticate_user(db: AsyncSession, email: str, password: str) -> Optional[User]:
    stmt = select(User).where(User.email == email.strip().lower())
    result = await db.execute(stmt)
    user = result.scalars().first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials or token expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    
    payload = decode_access_token(token)
    if not payload:
        raise credentials_exception
    
    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exception
    
    try:
        stmt = select(User).where(User.id == int(user_id))
        result = await db.execute(stmt)
        user = result.scalars().first()
        if user is None or not user.is_active:
            raise credentials_exception
        return user
    except ValueError:
        # sub might be email or invalid int
        stmt = select(User).where(User.email == str(user_id))
        result = await db.execute(stmt)
        user = result.scalars().first()
        if user is None or not user.is_active:
            raise credentials_exception
        return user

def require_roles(allowed_roles: List[str]):
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required role: {allowed_roles}, Your role: {current_user.role}"
            )
        return current_user
    return role_checker

require_admin = require_roles([UserRole.ADMIN.value])
require_analyst_or_admin = require_roles([UserRole.ADMIN.value, UserRole.ANALYST.value])
require_any_authenticated = require_roles([UserRole.ADMIN.value, UserRole.ANALYST.value, UserRole.AUDITOR.value])
