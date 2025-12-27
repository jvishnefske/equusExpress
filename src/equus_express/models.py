from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import (
    relationship,
    Session,
)
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    BLOB,
    ForeignKey,
    Boolean,
)
from equus_express.internal.session import Base

# --- Database Models (SQLAlchemy) ---
class User(Base):
    __tablename__ = "Users"
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String)
    password_salt = Column(String)
    # Passkey fields
    passkey_credential_id = Column(BLOB)
    passkey_public_key = Column(BLOB)
    passkey_sign_count = Column(Integer, default=0)
    # Account status and lockout
    account_status = Column(String, default="Active", nullable=False)
    last_login_at = Column(Integer)
    force_password_change = Column(
        Boolean, default=False, nullable=False
    )  # New field
    failed_login_attempts = Column(Integer, default=0)
    lockout_until = Column(Integer)
    created_at = Column(
        Integer, default=lambda: int(datetime.now().timestamp())
    )
    updated_at = Column(
        Integer,
        default=lambda: int(datetime.now().timestamp()),
        onupdate=lambda: int(datetime.now().timestamp()),
    )

    roles = relationship("UserRole", back_populates="user")
    groups = relationship("UserGroup", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class Role(Base):
    __tablename__ = "Roles"
    role_id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    created_at = Column(
        Integer, default=lambda: int(datetime.now().timestamp())
    )
    updated_at = Column(
        Integer,
        default=lambda: int(datetime.now().timestamp()),
        onupdate=lambda: int(datetime.now().timestamp()),
    )

    user_roles = relationship("UserRole", back_populates="role")
    role_permissions = relationship("RolePermission", back_populates="role")


class Permission(Base):
    __tablename__ = "Permissions"
    permission_id = Column(Integer, primary_key=True, index=True)
    permission_name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    created_at = Column(
        Integer, default=lambda: int(datetime.now().timestamp())
    )
    updated_at = Column(
        Integer,
        default=lambda: int(datetime.now().timestamp()),
        onupdate=lambda: int(datetime.now().timestamp()),
    )

    role_permissions = relationship(
        "RolePermission", back_populates="permission"
    )


class RolePermission(Base):
    __tablename__ = "RoleToPermission"
    role_id = Column(Integer, ForeignKey("Roles.role_id"), primary_key=True)
    permission_id = Column(
        Integer, ForeignKey("Permissions.permission_id"), primary_key=True
    )

    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")


class UserRole(Base):
    __tablename__ = "UserRoles"
    user_id = Column(Integer, ForeignKey("Users.user_id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("Roles.role_id"), primary_key=True)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="user_roles")


class Group(Base):
    __tablename__ = "Groups"
    group_id = Column(Integer, primary_key=True, index=True)
    group_name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    created_at = Column(
        Integer, default=lambda: int(datetime.now().timestamp())
    )
    updated_at = Column(
        Integer,
        default=lambda: int(datetime.now().timestamp()),
        onupdate=lambda: int(datetime.now().timestamp()),
    )

    user_groups = relationship("UserGroup", back_populates="group")


class UserGroup(Base):
    __tablename__ = "UserGroups"
    user_id = Column(Integer, ForeignKey("Users.user_id"), primary_key=True)
    group_id = Column(Integer, ForeignKey("Groups.group_id"), primary_key=True)

    user = relationship("User", back_populates="groups")
    group = relationship("Group", back_populates="user_groups")


class AuditLog(Base):
    __tablename__ = "AuditLog"
    log_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("Users.user_id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type = Column(String, nullable=False)
    event_description = Column(Text, nullable=False)
    ip_address = Column(String)
    timestamp = Column(
        Integer,
        default=lambda: int(datetime.now().timestamp()),
        nullable=False,
    )

    user = relationship("User", back_populates="audit_logs")


# --- Pydantic Models ---
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
