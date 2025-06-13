from fastapi import FastAPI, HTTPException, Depends, status, Query, Path, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator, root_validator, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    age: Optional[int] = Field(None, ge=0, le=120)
    
    @validator('name')
    def validate_name(cls, v):
        """USED by Pydantic"""
        if not v.isalpha():
            raise ValueError('Name must contain only letters')
        return v.title()
    
    @validator('email')
    def validate_email_domain(cls, v):
        """USED"""
        if not v.endswith('@company.com'):
            raise ValueError('Email must be from company domain')
        return v

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def validate_password(cls, v):
        """USED"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        return v

class UserResponse(UserBase):
    id: int
    created_at: datetime
    is_active: bool = True
    
    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    age: Optional[int] = None

class UserStats(BaseModel):
    """UNUSED MODEL"""
    login_count: int = 0
    last_login: Optional[datetime] = None
    posts_count: int = 0
    
    @validator('login_count')
    def validate_login_count(cls, v):
        """UNUSED"""
        if v < 0:
            raise ValueError('Login count cannot be negative')
        return v

class UserPreferences(BaseModel):
    """UNUSED MODEL"""
    theme: str = 'light'
    notifications: bool = True
    language: str = 'en'
    
    @root_validator
    def validate_preferences(cls, values):
        """UNUSED"""
        if values.get('theme') not in ['light', 'dark']:
            raise ValueError('Invalid theme')
        return values

app = FastAPI(
    title="Test User API",
    description="API for managing fake users with FastAPI",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """USED"""
    token = credentials.credentials
    if token == "invalid":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return {"user_id": 1, "username": "testuser"}

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    """USED"""
    if not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

async def get_db_connection():
    """UNUSED"""
    try:
        yield {"connection": "mock_db"}
    finally:
        pass

async def validate_api_key(api_key: str = Query(...)):
    """UNUSED"""
    if api_key != "secret-key":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

@app.get("/", response_model=Dict[str, str])
async def root():
    """Used"""
    return {"message": "User Management API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}

@app.get("/users", response_model=List[UserResponse])
async def get_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """Get list of users"""
    users = [
        {
            "id": 1,
            "name": "John smith",
            "email": "john@abc.com",
            "age": 20,
            "created_at": datetime.now(),
            "is_active": True
        }
    ]
    return users[skip:skip + limit]

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int = Path(..., ge=1),
    current_user: dict = Depends(get_current_user)
):
    if user_id == 999:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user_id,
        "name": "John smith",
        "email": "john@company.com",
        "age": 20,
        "created_at": datetime.now(),
        "is_active": True
    }

@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    current_user: dict = Depends(get_admin_user)
):

    new_user = {
        "id": 123,
        "name": user.name,
        "email": user.email,
        "age": user.age,
        "created_at": datetime.now(),
        "is_active": True
    }
    return new_user

@app.get("/users/{user_id}/stats")
async def get_user_stats(
    user_id: int = Path(..., ge=1),
    current_user: dict = Depends(get_current_user)
):
    """UNUSED"""
    if user_id == 999:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "user_id": user_id,
        "login_count": 42,
        "last_login": datetime.now(),
        "posts_count": 15
    }

@app.post("/users/{user_id}/preferences")
async def update_user_preferences(
    preferences: UserPreferences = Body(...),
):
    """UNUSED ENDPOINT"""
    return {"message": "Preferences updated", "preferences": preferences}

@app.post("/users/bulk-import")
async def bulk_import_users(
    users: List[UserCreate] = Body(...),
    admin_user: dict = Depends(get_admin_user)
):
    """Bulk import users - UNUSED ENDPOINT"""
    # Bulk import functionality that's never used
    created_users = []
    for user in users:
        created_users.append({
            "id": len(created_users) + 1,
            "name": user.name,
            "email": user.email
        })
    
    return {"imported": len(created_users), "users": created_users}

async def validate_user_exists(user_id: int) -> bool:
    """USED"""
    return user_id != 999

@app.on_event("startup")
async def setup_background_tasks():
    """ UNUSED"""
    logging.info("Setting up background tasks...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)