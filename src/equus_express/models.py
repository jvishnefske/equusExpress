from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str = Field(
        ..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$"
    )
    password: str = Field(..., min_length=8)
    is_super_admin: bool = False

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("String should have at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError(
                "Password must contain at least one uppercase letter"
            )
        if not any(c.islower() for c in v):
            raise ValueError(
                "Password must contain at least one lowercase letter"
            )
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError(
                "Password must contain at least one special character"
            )
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class UserUpdate(BaseModel):
    username: Optional[str] = Field(
        None, min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$"
    )
    account_status: Optional[str] = Field(
        None, pattern=r"^(Active|Disabled|Locked)$"
    )


class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("String should have at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError(
                "Password must contain at least one uppercase letter"
            )
        if not any(c.islower() for c in v):
            raise ValueError(
                "Password must contain at least one lowercase letter"
            )
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError(
                "Password must contain at least one special character"
            )
        return v


class UserResponse(BaseModel):
    user_id: int
    username: str
    account_status: str
    last_login_at: Optional[int]
    created_at: int
    updated_at: int
    roles: List[str] = []
    groups: List[str] = []
    passkey_credential_id: Optional[str] = None  # Base64URL encoded


class RoleCreate(BaseModel):
    role_name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None


class RoleResponse(BaseModel):
    role_id: int
    role_name: str
    description: Optional[str]
    created_at: int
    updated_at: int
    permissions: List[str] = []


class GroupCreate(BaseModel):
    group_name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None


class GroupResponse(BaseModel):
    group_id: int
    group_name: str
    description: Optional[str]
    created_at: int
    updated_at: int


class AuditLogResponse(BaseModel):
    log_id: int
    user_id: Optional[int]
    username: Optional[str]
    event_type: str
    event_description: str
    ip_address: Optional[str]
    timestamp: int


class PasskeyRegistrationStart(BaseModel):
    username: str


class PasskeyRegistrationComplete(BaseModel):
    username: str
    attestation_response: dict


class PasskeyAuthenticationStart(BaseModel):
    username: str


class PasskeyAuthenticationComplete(BaseModel):
    username: str
    assertion_response: dict
