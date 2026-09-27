from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.security import create_access_token
from app.models.user import User
from app.schemas.user import LoginRequest, TokenResponse, UserOut
from app.services.auth_service import authenticate_user, get_current_user
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    user = await authenticate_user(db, login_data.email, login_data.password)
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")

    if not user:
        await log_audit_event(
            db=db,
            action="AUTH_LOGIN_FAILED",
            resource="auth",
            actor_email=login_data.email,
            actor_role="unknown",
            status="FAILED",
            ip_address=client_ip,
            user_agent=user_agent,
            details={"reason": "Invalid credentials"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is deactivated"
        )
    
    user_id = user.id
    user_role = user.role

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    try:
        await db.commit()
    except Exception: # pylint: disable=broad-exception-caught
        await db.rollback()
    
    # Create token
    access_token = create_access_token(subject=user_id, role=user_role)
    
    await log_audit_event(
        db=db,
        action="AUTH_LOGIN_SUCCESS",
        resource="auth",
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role,
        status="SUCCESS",
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await log_audit_event(
        db=db,
        action="AUTH_LOGOUT",
        resource="auth",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        status="SUCCESS",
        ip_address=client_ip
    )
    return {"message": "Successfully logged out"}
