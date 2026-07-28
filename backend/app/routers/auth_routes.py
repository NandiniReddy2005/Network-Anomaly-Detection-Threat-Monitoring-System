from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional, List
import logging

logger = logging.getLogger("netshield_auth")

try:
    from app.database import get_db
    from app.models import User
    from app.auth import hash_password, verify_password
except ImportError:
    from backend.app.database import get_db
    from backend.app.models import User
    from backend.app.auth import hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = "analyst"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@router.post("/register")
async def register_user(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    if not req.email or not req.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required."
        )
    
    if req.role not in ["analyst", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role specified."
        )

    try:
        # Check if email already exists
        result = await db.execute(select(User).where(User.email == req.email.lower()))
        existing_user = result.scalars().first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists."
            )

        # Hash password & create user
        hashed_pwd = hash_password(req.password)
        new_user = User(
            email=req.email.lower(),
            password_hash=hashed_pwd,
            role=req.role
        )
        db.add(new_user)
        await db.flush()
        
        user_id = new_user.id
        user_email = new_user.email
        user_role = new_user.role

        await db.commit()

        return {
            "status": "success",
            "message": "User registered successfully.",
            "user": {
                "id": user_id,
                "email": user_email,
                "role": user_role
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        err_msg = str(e)
        logger.error(f"Error during registration for {req.email}: {err_msg}")
        if "10061" in err_msg or "ConnectionRefused" in err_msg or "refused" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is starting up. Please try again in a few seconds."
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration error: {err_msg}"
        )

@router.post("/login")
async def login_user(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    if not req.email or not req.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please enter your email and password."
        )

    try:
        # Find user by email
        result = await db.execute(select(User).where(User.email == req.email.lower()))
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Account not found. Please register first."
            )

        if not verify_password(req.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password."
            )

        user_id = user.id
        user_email = user.email
        user_role = user.role

        return {
            "status": "success",
            "message": "Authentication successful.",
            "user": {
                "id": user_id,
                "email": user_email,
                "role": user_role
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        err_msg = str(e)
        logger.error(f"Error during login for {req.email}: {err_msg}")
        if "10061" in err_msg or "ConnectionRefused" in err_msg or "refused" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is starting up. Please try again in a few seconds."
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {err_msg}"
        )

@router.get("/users")
async def get_all_users(db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(User))
        users = result.scalars().all()
        user_list = [
            {
                "email": u.email,
                "role": "Security Analyst" if u.role == "analyst" else "Security Administrator",
                "access": "Read / Monitor / Triage" if u.role == "analyst" else "Full Global Control",
                "status": "Active"
            }
            for u in users
        ]
        return {
            "status": "success",
            "data": user_list
        }
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return {"status": "success", "data": []}
