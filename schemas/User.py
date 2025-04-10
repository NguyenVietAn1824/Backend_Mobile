from typing import Any
from datetime import datetime
from pydantic import BaseModel, UUID4, field_validator, EmailStr, Field
import uuid
from typing import Optional
class UserBase(BaseModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str
    
class User(UserBase):
    """
    Class này check thông tin của User khi backend trả về thông tin của User
    """
    id: int
    class Config:
        from_attributes = True
class UserRegister(UserBase):
    password: str
    confirm_password: str

    @field_validator("confirm_password")
    def verify_password_match(cls, v: str, info: Any) -> str:
        password = info.data.get('password')
        if v != password:
            raise ValueError("The two passwords did not match.")
        return v
    
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    
class JwtTokenSchema(BaseModel):
    token: str
    payload: dict
    expire: datetime

class TokenPair(BaseModel):
    access: JwtTokenSchema
    refresh: JwtTokenSchema

class RefreshToken(BaseModel):
    refresh: str

class MailBodySchema(BaseModel):
    token: str
    type: str
    
class MailTaskSchema(BaseModel):
    user: User
    body: MailBodySchema

class ForgotPasswordSchema(BaseModel):
    email: EmailStr
    
class PasswordResetSchema(BaseModel):
    password: str
    confirm_password: str

    @field_validator("confirm_password")
    def verify_password_match(cls, v: str, info: Any) -> str:
        password = info.data.get('password')
        if v != password:
            raise ValueError("The two passwords did not match.")
        return v

## Update password
class UpdatePasswordSchema(PasswordResetSchema):
    old_password: str


