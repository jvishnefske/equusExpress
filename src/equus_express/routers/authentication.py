import hashlib
import logging
import os # Keep for os.getenv
import secrets
import shutil # For rmtree
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import fastapi
import uvicorn
from pathlib import Path

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from contextlib import asynccontextmanager

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    BLOB,
    ForeignKey,
    Boolean,
)
from sqlalchemy.orm import (
    relationship,
    Session,
)
from webauthn import verify_registration_response, base64url_to_bytes, generate_authentication_options, \
    verify_authentication_response

# For WebAuthn (Passkeys)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
)
from equus_express.models import *
# Import SessionLocal, Base, engine, and get_db from the new module
from equus_express.internal.session import SessionLocal, Base, engine, get_db
# Import common exceptions and models
from equus_express.exceptions import (
    HTTPException,
    status,
    UserNotFoundException,
    RoleNotFoundException,
    PermissionNotFoundException,
    GroupNotFoundException,
    PasskeyNotFoundException,
    MissingChallengeDataException,
    PasskeyRegistrationFailedException,
    PasskeyAuthenticationFailedException,
    ReplayAttackDetectedException,
    InvalidCredentialsException,
    IncorrectCredentialsException,
    AccountLockedException,
    AccountDisabledException,
    PermissionNotDefinedException,
    ForbiddenException,
    SuperAdminCreationForbiddenException,
    UsernameAlreadyRegisteredException,
    FrontendFileNotFoundException,
    RoleNameAlreadyExistsException,
    LastSuperAdminRoleDeletionForbiddenException,
    SelfAccountStatusModificationForbiddenException,
    SelfDeletionForbiddenException,
    LastSuperAdminDeletionForbiddenException,
    IncorrectCurrentPasswordException,
    RoleAlreadyExistsException,
    PermissionAlreadyAssignedException,
    RoleAlreadyAssignedToUserException,
    LastSuperAdminRoleRemovalForbiddenException,
    GroupNameAlreadyExistsException,
    GroupAlreadyExistsException,
    UserAlreadyAssignedToGroupException,
    UserNotInGroupException,
    InvalidEmergencyCodeException,
)
from equus_express.models import (
    User,
    Token,
    UserCreate,
    UserLogin,
    UserUpdate,
    PasswordChange,
    UserResponse,
    RoleCreate,
    RoleResponse,
    GroupCreate,
    GroupResponse,
    AuditLogResponse,
    PasskeyRegistrationStart,
    PasskeyRegistrationComplete,
    PasskeyAuthenticationStart,
    PasskeyAuthenticationComplete,
    Role,
)


# Import EQUUS_DATA_DIR, Path from internal config if available or redefine locally
# Assuming EQUUS_DATA_DIR will be centralized in config.py later or managed by the app where needed.
from pathlib import Path

ADMINISTRATOR = "Super Administrator"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30

# SQLite Database Configuration (now defined in equus_express.internal.session.py)
# Only define EQUUS_DATA_DIR here if it's used *only* for file paths like the initial password file.
# If it's used to derive DATABASE_URL, that should be handled in session.py.
# For now, keeping the Path import and definition if it's strictly for local file system ops.
EQUUS_DATA_DIR_STR = os.getenv("EQUUS_DATA_DIR", "./data")
EQUUS_DATA_DIR = Path(EQUUS_DATA_DIR_STR)

# OAuth2 Scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/password")

# WebAuthn Configuration
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = "Local Admin Portal"
# Allow both localhost and 127.0.0.1 for local development
WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")
ALLOWED_ORIGINS = [WEBAUTHN_ORIGIN, "http://127.0.0.1:8000"]
router = fastapi.APIRouter()

# --- Database Initialization ---
def create_db_and_tables(db: Session):
    # This function ensures that roles and permissions are always present within the provided db session.
    # It also handles the creation of the initial superadmin if no users exist.

    # Create default role if it doesn't exist
    super_admin_role = db.query(Role).filter_by(role_name=ADMINISTRATOR).first()
    if not super_admin_role:
        super_admin_role = Role(role_name=ADMINISTRATOR, description="Full administrative access.")
        db.add(super_admin_role)
        db.commit()
        db.refresh(super_admin_role)
        logger.info(f"Created default role: {super_admin_role.role_name}")

    # Ensure all permissions exist and assign to Super Administrator role
    permissions_to_ensure = [
        ("manage_users", "Ability to create, update, delete users."),
        ("manage_roles", "Ability to create, update, delete roles and assign permissions to roles."),
        ("manage_groups", "Ability to create, update, delete groups and assign users to groups."),
        ("view_audit_logs", "Ability to view audit logs."),
        ("assign_roles", "Ability to assign roles to users."),
        ("assign_groups", "Ability to assign groups to users."),
        ("emergency_access", "Emergency access for break-glass scenarios."),
    ]

    existing_permissions = {p.permission_name: p for p in db.query(Permission).all()}
    for perm_name, perm_desc in permissions_to_ensure:
        if perm_name not in existing_permissions:
            new_perm = Permission(permission_name=perm_name, description=perm_desc)
            db.add(new_perm)
            db.flush()  # Flush to get ID for assignment
            existing_permissions[perm_name] = new_perm  # Add to map for immediate use
            logger.info(f"Created permission: {perm_name}")

        # Assign to Super Administrator role if not already assigned
        perm_obj = existing_permissions[perm_name]
        if super_admin_role and not db.query(RolePermission).filter_by(
            role_id=super_admin_role.role_id, permission_id=perm_obj.permission_id
        ).first():
            db.add(RolePermission(role_id=super_admin_role.role_id, permission_id=perm_obj.permission_id))
            logger.info(f"Assigned permission {perm_name} to Super Administrator role.")
    db.commit()
    logger.info("Ensured default roles and permissions are in place and assigned to Super Administrator.")

    # Create initial superadmin user if no users exist
    if db.query(User).count() == 0:
        superadmin_username = "superadmin"
        # Generate a random password that meets all complexity requirements
        import string
        temp_password_chars = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice('!@#$%^&*()_+-=[]{}|;:,.<>?'),
        ]
        # Fill the rest of the 16 characters randomly from all allowed printable characters
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        temp_password_chars += [secrets.choice(all_chars) for _ in range(16 - len(temp_password_chars))]
        secrets.SystemRandom().shuffle(temp_password_chars) # Shuffle to randomize order
        temp_password = "".join(temp_password_chars)
        password_hash, salt = hash_password(temp_password)

        initial_superadmin = User(
            username=superadmin_username,
            password_hash=password_hash,
            password_salt=salt,
            account_status="Active",
            force_password_change=True,  # Force password change on first login
            last_login_at=int(datetime.now().timestamp()), # Set initial login time for consistency
        )
        db.add(initial_superadmin)
        db.flush() # Flush to get user_id

        user_role = UserRole(user_id=initial_superadmin.user_id, role_id=super_admin_role.role_id)
        db.add(user_role)
        db.commit()
        db.refresh(initial_superadmin)
        db.refresh(super_admin_role)

        # Log and save the initial password to the directory where the SQLite DB is stored
        db_dir = EQUUS_DATA_DIR
        # Ensure the directory exists before writing the file
        Path(db_dir).mkdir(parents=True, exist_ok=True)
        initial_password_file_path = Path(db_dir) / "initial_superadmin_password.txt"
        with open(initial_password_file_path, "w") as f:
            f.write(f"Initial Super Admin Username: {superadmin_username}\n")
            f.write(f"Initial Super Admin Password: {temp_password}\n")
        logger.info(
            f"Created initial superadmin user '{superadmin_username}' with a randomly generated password. "
            f"Password logged to '{initial_password_file_path}' for first-time use. User must change password on first login."
        )




# --- Security Utilities ---
def hash_password(password: str) -> tuple[str, str]:
    """Hash password and return (hash, salt)"""
    salt = secrets.token_hex(32)
    password_hash = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        iterations=100000,
    )
    return password_hash.hex(), salt


def verify_password(
    plain_password: str, hashed_password: str, salt: str
) -> bool:
    """Verify password with salt"""
    # Re-calculate the hash with the provided salt and plain password
    re_hashed_password = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=plain_password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        iterations=100000,
    ).hex() # Convert to hex string for comparison

    return re_hashed_password == hashed_password


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def log_audit_event(
    db: Session,
    user_id: Optional[int],
    event_type: str,
    description: str,
    ip_address: Optional[str] = None,
):
    """Log audit event"""
    audit_log = AuditLog(
        user_id=user_id,
        event_type=event_type,
        event_description=description,
        ip_address=ip_address,
    )
    db.add(audit_log)
    db.commit()


def is_account_locked(user: User) -> bool:
    """Check if account is locked due to failed attempts"""
    if user.lockout_until and user.lockout_until > int(
        datetime.now().timestamp()
    ):
        return True
    return False


def lock_account(db: Session, user: User, ip_address: str):
    """Lock account after too many failed attempts"""
    user.lockout_until = int(
        (
            datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        ).timestamp()
    )
    user.account_status = "Locked"
    db.commit()
    log_audit_event(
        db,
        user.user_id,
        "ACCOUNT_LOCKED",
        f"Account locked due to {MAX_FAILED_ATTEMPTS} failed login attempts",
        ip_address,
    )


def reset_failed_attempts(db: Session, user: User):
    """Reset failed login attempts on successful login"""
    user.failed_login_attempts = 0
    user.lockout_until = None
    if user.account_status == "Locked":
        user.account_status = "Active"
    db.commit()


def get_client_ip(request: Request) -> str:
    """Get client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise InvalidCredentialsException()
    except JWTError:
        raise InvalidCredentialsException()

    user = db.query(User).filter(User.username == username).first()
    if user is None or user.account_status not in [
        "Active",
        "Locked",
    ]:  # Allow locked accounts to be processed for lockout checks
        raise InvalidCredentialsException()
    return user


def has_permission(permission_name: str):
    """Dependency factory for permission checking"""

    def check_permission(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        user_roles = (
            db.query(UserRole)
            .filter(UserRole.user_id == current_user.user_id)
            .all()
        )
        role_ids = [ur.role_id for ur in user_roles]

        required_permission = (
            db.query(Permission)
            .filter(Permission.permission_name == permission_name)
            .first()
        )
        if not required_permission:
            raise PermissionNotDefinedException(permission_name)

        for role_id in role_ids:
            if (
                db.query(RolePermission)
                .filter(
                    RolePermission.role_id == role_id,
                    RolePermission.permission_id
                    == required_permission.permission_id,
                )
                .first()
            ):
                return True

        raise ForbiddenException(
            detail=f"User does not have '{permission_name}' permission."
        )

    return check_permission


# --- FastAPI App Setup ---








@router.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the static admin portal frontend HTML file."""
    html_file_path = Path(__file__).parent / "admin_portal_frontend.html"
    if not html_file_path.is_file():
        raise FrontendFileNotFoundException()
    return html_file_path.read_text()


# --- Authentication Endpoints ---
@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate, request: Request, db: Session = Depends(get_db)
):
    """Register a new user (only allows super admin for first user)"""
    existing_users = db.query(User).count()

    # Only allow super admin creation if no users exist
    if existing_users > 0 and user_data.is_super_admin:
        raise SuperAdminCreationForbiddenException()

    # Check if username already exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise UsernameAlreadyRegisteredException()

    # Hash password with salt
    password_hash, salt = hash_password(user_data.password)

    # Create user
    user = User(
        username=user_data.username,
        password_hash=password_hash,
        password_salt=salt,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Assign Super Administrator role if requested and allowed
    if user_data.is_super_admin and existing_users == 0:
        super_admin_role = (
            db.query(Role)
            .filter(Role.role_name == ADMINISTRATOR)
            .first()
        )
        if super_admin_role:
            user_role = UserRole(
                user_id=user.user_id, role_id=super_admin_role.role_id
            )
            db.add(user_role)
            db.commit()

    log_audit_event(
        db,
        user.user_id,
        "USER_CREATED",
        f"User {user.username} created",
        get_client_ip(request),
    )

    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        account_status=user.account_status,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        roles=[],
        groups=[],
        passkey_credential_id=(
            user.passkey_credential_id.decode("latin1")
            if user.passkey_credential_id
            else None
        ),
    )


@router.post("/login/password", response_model=Token)
async def login_password(
    user_credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    """Login with username and password"""
    user = (
        db.query(User)
        .filter(User.username == user_credentials.username)
        .first()
    )
    client_ip = get_client_ip(request)

    if not user:
        log_audit_event(
            db,
            None,
            "LOGIN_FAILED",
            f"Login attempt with non-existent username: {user_credentials.username}",
            client_ip,
        )
        raise IncorrectCredentialsException()

    # Check if account is locked
    if is_account_locked(user):
        log_audit_event(
            db,
            user.user_id,
            "LOGIN_BLOCKED",
            "Login attempt on locked account",
            client_ip,
        )
        raise AccountLockedException()

    # Check if account is disabled
    if user.account_status == "Disabled":
        log_audit_event(
            db,
            user.user_id,
            "LOGIN_BLOCKED",
            "Login attempt on disabled account",
            client_ip,
        )
        raise AccountDisabledException()

    # Verify password
    if not verify_password(
        user_credentials.password, user.password_hash, user.password_salt
    ):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            lock_account(db, user, client_ip)
        else:
            db.commit()

        log_audit_event(
            db,
            user.user_id,
            "LOGIN_FAILED",
            f"Invalid password attempt ({user.failed_login_attempts}/{MAX_FAILED_ATTEMPTS})",
            client_ip,
        )
        raise IncorrectCredentialsException()

    # Successful login
    reset_failed_attempts(db, user)
    user.last_login_at = int(datetime.now().timestamp())

    # If force_password_change is true, set it to false after successful initial login
    if user.force_password_change:
        user.force_password_change = False # User has logged in with initial password, now they will be prompted to change
    db.commit()

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    log_audit_event(
        db,
        user.user_id,
        "LOGIN_SUCCESS",
        "Successful password login",
        client_ip,
    )

    return {"access_token": access_token, "token_type": "bearer"}


# --- Utility Endpoints for Current User ---
@router.get("/me/passkeys")
async def get_my_passkeys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get credential ID for current user's passkey (if any)"""
    if current_user.passkey_credential_id:
        return {
            "credential_id": base64url_to_bytes(
                current_user.passkey_credential_id
            ).decode("latin1")
        }
    raise PasskeyNotFoundException(detail="No passkey registered for this user")


@router.delete("/me/passkeys")
async def delete_my_passkey(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user), # Use Depends directly
):
    """Delete current user's registered passkey"""
    if not current_user.passkey_credential_id:
        raise PasskeyNotFoundException(detail="No passkey to delete for this user")

    credential_id_hex = current_user.passkey_credential_id
    current_user.passkey_credential_id = None
    current_user.passkey_public_key = None
    current_user.passkey_sign_count = 0
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "PASSKEY_DELETED",
        f"User {current_user.username} deleted their passkey (ID: {credential_id_hex[:10]}...)",
        get_client_ip(request),
    )
    return {"message": "Passkey deleted successfully"}


# --- WebAuthn (Passkey) Endpoints ---
@router.post("/passkey/register/start")
async def passkey_register_start(
    request_data: PasskeyRegistrationStart,
    request: Request,
    db: Session = Depends(get_db),
):
    """Start passkey registration process"""
    user = (
        db.query(User).filter(User.username == request_data.username).first()
    )
    if not user:
        raise UserNotFoundException()

    # Generate registration options
    # The `webauthn` library handles its own state internally, for now, we'll
    # return the challenge directly in the options to the client.
    # We will need to store the challenge server-side for verification.
    # For simplicity in this example, the client will send it back.
    # In a production environment, this should be stored securely server-side
    # (e.g., in a Redis cache with a short TTL, or a temporary DB table).
    registration_options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=[],  # For registration, we don't allow existing credentials
    )

    log_audit_event(
        db,
        user.user_id,
        "PASSKEY_REGISTER_START",
        "Started passkey registration",
        get_client_ip(request),
    )

    return {
        "publicKey": registration_options.json(),  # Return the options as JSON string
        # The challenge is part of publicKey.challenge. It needs to be stored and validated later.
        # For simplicity, we are assuming the client will return the original challenge or we retrieve it from the options object.
        # This approach for 'state' is simplified for example purposes.
        "state": registration_options.challenge.decode("utf-8"),
    }


@router.post("/passkey/register/complete")
async def passkey_register_complete(
    request_data: PasskeyRegistrationComplete,
    request: Request,
    db: Session = Depends(get_db),
):
    """Complete passkey registration process"""
    user = (
        db.query(User).filter(User.username == request_data.username).first()
    )
    if not user:
        raise UserNotFoundException()

    try:
        # In a real implementation, retrieve the challenge (state) from session or database
        # For this example, we assume `state` in `attestation_response` directly contains the challenge
        expected_challenge_b64url = request_data.attestation_response.get(
            "state"
        )
        if not expected_challenge_b64url:
            raise MissingChallengeDataException()

        verified_credential = verify_registration_response(
            credential=request_data.attestation_response,
            expected_challenge=base64url_to_bytes(expected_challenge_b64url),
            expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID,
            require_user_verification=False,  # Depends on your policy
        )

        # Store credential
        user.passkey_credential_id = verified_credential.credential_id
        user.passkey_public_key = verified_credential.credential_public_key
        user.passkey_sign_count = verified_credential.sign_count
        db.commit()

        log_audit_event(
            db,
            user.user_id,
            "PASSKEY_REGISTERED",
            "Passkey successfully registered",
            get_client_ip(request),
        )

        return {
            "status": "success",
            "message": "Passkey registered successfully",
        }

    except Exception as e:
        logger.error(
            f"Passkey registration failed for user {request_data.username}: {e}",
            exc_info=True,
        )
        log_audit_event(
            db,
            user.user_id,
            "PASSKEY_REGISTER_FAILED",
            f"Passkey registration failed: {str(e)}",
            get_client_ip(request),
        )
        raise PasskeyRegistrationFailedException(detail=f"Passkey registration failed: {e}")


@router.post("/passkey/authenticate/start")
async def passkey_authenticate_start(
    request_data: PasskeyAuthenticationStart,
    request: Request,
    db: Session = Depends(get_db),
):
    """Start passkey authentication process"""
    user = (
        db.query(User).filter(User.username == request_data.username).first()
    )
    if not user: # Handle user not found separately
        raise UserNotFoundException()
    if not user.passkey_credential_id: # Handle passkey not found
        raise PasskeyNotFoundException()


    # Check account status
    if is_account_locked(user):
        raise AccountLockedException()
    if user.account_status != "Active":
        raise AccountDisabledException()

    # Generate authentication options
    auth_options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=user.passkey_credential_id,
                transports=[
                    "internal",
                    "hybrid",
                    "usb",
                    "nfc",
                    "ble",
                ],  # Include relevant transports
            )
        ],
        user_verification="preferred",  # Or "required" if strict UV is needed
    )

    log_audit_event(
        db,
        user.user_id,
        "PASSKEY_AUTH_START",
        "Started passkey authentication",
        get_client_ip(request),
    )

    # In a real app, store auth_options.challenge and other state securely server-side.
    # For this example, we return the challenge in the response for the client to send back.
    return {
        "publicKey": auth_options.json(),
        "state": auth_options.challenge.decode("utf-8"),
    }


@router.post("/passkey/authenticate/complete", response_model=Token)
async def passkey_authenticate_complete(
    request_data: PasskeyAuthenticationComplete,
    request: Request,
    db: Session = Depends(get_db),
):
    """Complete passkey authentication process"""
    user = (
        db.query(User).filter(User.username == request_data.username).first()
    )
    if (
        not user
        or not user.passkey_credential_id
        or not user.passkey_public_key
    ):
        raise UserNotFoundException() # If user not found
    if not user.passkey_credential_id or not user.passkey_public_key:
        raise PasskeyNotFoundException() # If passkey data is missing

    try:
        # Retrieve the challenge (state) from the request, sent back by the client.
        # In a real implementation, this would be retrieved from a server-side store
        # using a session ID or similar identifier.
        expected_challenge_b64url = request_data.assertion_response.get(
            "state"
        )
        if not expected_challenge_b64url:
            raise MissingChallengeDataException()

        verified_authentication = verify_authentication_response(
            credential=request_data.assertion_response,
            expected_challenge=base64url_to_bytes(expected_challenge_b64url),
            expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID,
            credential_public_key=user.passkey_public_key,
            credential_current_sign_count=user.passkey_sign_count,
            require_user_verification=False,  # Must match the options sent at start
        )

        # Update sign count to prevent replay attacks
        if verified_authentication.new_sign_count <= user.passkey_sign_count:
            raise ReplayAttackDetectedException()

        user.passkey_sign_count = verified_authentication.new_sign_count
        user.last_login_at = int(datetime.now().timestamp())
        reset_failed_attempts(db, user)
        db.commit()

        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )

        log_audit_event(
            db,
            user.user_id,
            "LOGIN_SUCCESS",
            "Successful passkey authentication",
            get_client_ip(request),
        )

        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            lock_account(db, user, get_client_ip(request))
        else:
            db.commit()

        log_audit_event(
            db,
            user.user_id,
            "LOGIN_FAILED",
            f"Passkey authentication failed: {str(e)}",
            get_client_ip(request),
        )
        raise PasskeyAuthenticationFailedException()


# --- User Management Endpoints ---
@router.get("/users", response_model=List[UserResponse])
async def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_users")),
):
    """Get all users (requires manage_users permission)"""
    users = db.query(User).all()
    result = []

    for user in users:
        # Get user roles
        user_roles = (
            db.query(UserRole).filter(UserRole.user_id == user.user_id).all()
        )
        roles = []
        for ur in user_roles:
            role = db.query(Role).filter(Role.role_id == ur.role_id).first()
            if role:
                roles.append(role.role_name)

        # Get user groups
        user_groups = (
            db.query(UserGroup).filter(UserGroup.user_id == user.user_id).all()
        )
        groups = []
        for ug in user_groups:
            group = (
                db.query(Group).filter(Group.group_id == ug.group_id).first()
            )
            if group:
                groups.append(group.group_name)

        result.append(
            UserResponse(
                user_id=user.user_id,
                username=user.username,
                account_status=user.account_status,
                last_login_at=user.last_login_at,
                created_at=user.created_at,
                updated_at=user.updated_at,
                roles=roles,
                groups=groups,
                passkey_credential_id=(
                    user.passkey_credential_id.decode("latin1")
                    if user.passkey_credential_id
                    else None
                ),
            )
        )

    return result


@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: int,
    role_update: RoleCreate,  # Re-using RoleCreate as it has name and description fields
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Update role name or description"""
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise RoleNotFoundException()

    old_name = role.role_name
    old_description = role.description

    if role_update.role_name and role_update.role_name != role.role_name:
        # Check if new role name already exists
        if (
            db.query(Role)
            .filter(
                Role.role_name == role_update.role_name,
                Role.role_id != role_id,
            )
            .first()
        ):
            raise RoleNameAlreadyExistsException()
        role.role_name = role_update.role_name

    if (
        role_update.description is not None
    ):  # Allow description to be explicitly set to None (empty)
        role.description = role_update.description

    role.updated_at = int(datetime.now().timestamp())
    db.commit()

    changes = []
    if old_name != role.role_name:
        changes.append(f"name: {old_name} -> {role.role_name}")
    if old_description != role.description:
        changes.append(
            f"description: '{old_description}' -> '{role.description}'"
        )

    if changes:
        log_audit_event(
            db,
            current_user.user_id,
            "ROLE_UPDATED",
            f"Updated role {role.role_name} (ID: {role_id}): {', '.join(changes)}",
            get_client_ip(request),
        )

    # Get role permissions for the response
    role_perms = (
        db.query(RolePermission)
        .filter(RolePermission.role_id == role.role_id)
        .all()
    )
    permissions = []
    for rp in role_perms:
        perm = (
            db.query(Permission)
            .filter(Permission.permission_id == rp.permission_id)
            .first()
        )
        if perm:
            permissions.append(perm.permission_name)

    return RoleResponse(
        role_id=role.role_id,
        role_name=role.role_name,
        description=role.description,
        created_at=role.created_at,
        updated_at=role.updated_at,
        permissions=permissions,
    )


@router.delete("/roles/{role_id}")
async def delete_role(
    role_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Delete a role"""
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise RoleNotFoundException()

    # Prevent deleting Super Administrator role if it's the only one or still assigned to users
    if role.role_name == ADMINISTRATOR:
        # Check if any user still has this role
        if db.query(UserRole).filter(UserRole.role_id == role.role_id).first():
            raise LastSuperAdminRoleDeletionForbiddenException(
                detail="Cannot delete 'Super Administrator' role if it's assigned to any user or is the only one."
            )
        # Check if there are other super admins if it's the last one
        total_super_admins_in_roles_table = (
            db.query(Role)
            .filter(Role.role_name == ADMINISTRATOR)
            .count()
        )
        if total_super_admins_in_roles_table <= 1:
            raise LastSuperAdminRoleDeletionForbiddenException(
                detail="Cannot delete the last 'Super Administrator' role definition."
            )

    # Remove all associated UserRole and RolePermission entries
    db.query(UserRole).filter(UserRole.role_id == role_id).delete()
    db.query(RolePermission).filter(RolePermission.role_id == role_id).delete()

    db.delete(role)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "ROLE_DELETED",
        f"Deleted role: {role.role_name} (ID: {role_id})",
        get_client_ip(request),
    )
    return {"message": "Role deleted successfully"}


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_users")),
):
    """Get specific user by ID"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    # Get user roles
    user_roles = (
        db.query(UserRole).filter(UserRole.user_id == user.user_id).all()
    )
    roles = []
    for ur in user_roles:
        role = db.query(Role).filter(Role.role_id == ur.role_id).first()
        if role:
            roles.append(role.role_name)

    # Get user groups
    user_groups = (
        db.query(UserGroup).filter(UserGroup.user_id == user.user_id).all()
    )
    groups = []
    for ug in user_groups:
        group = db.query(Group).filter(Group.group_id == ug.group_id).first()
        if group:
            groups.append(group.group_name)

    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        account_status=user.account_status,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        roles=roles,
        groups=groups,
        passkey_credential_id=(
            user.passkey_credential_id.decode("latin1")
            if user.passkey_credential_id
            else None
        ),
    )


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_users")),
):
    """Update user information"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    # Prevent self-modification of account status
    if user.user_id == current_user.user_id and user_update.account_status:
        raise SelfAccountStatusModificationForbiddenException()

    old_values = {
        "username": user.username,
        "account_status": user.account_status,
    }

    if user_update.username:
        # Check if new username already exists
        existing_user = (
            db.query(User)
            .filter(
                User.username == user_update.username, User.user_id != user_id
            )
            .first()
        )
        if existing_user:
            raise UsernameAlreadyRegisteredException()
        user.username = user_update.username

    if user_update.account_status:
        user.account_status = user_update.account_status
        if user_update.account_status == "Active":
            user.failed_login_attempts = 0
            user.lockout_until = None

    user.updated_at = int(datetime.now().timestamp())
    db.commit()

    changes = []
    if old_values["username"] != user.username:
        changes.append(f"username: {old_values['username']} → {user.username}")
    if old_values["account_status"] != user.account_status:
        changes.append(
            f"status: {old_values['account_status']} → {user.account_status}"
        )

    if changes:
        log_audit_event(
            db,
            current_user.user_id,
            "USER_UPDATED",
            f"Updated user {user.username} (ID: {user.user_id}): {', '.join(changes)}",
            get_client_ip(request),
        )

    # Re-fetch roles and groups after changes for the response
    user_roles_db = (
        db.query(UserRole).filter(UserRole.user_id == user.user_id).all()
    )
    roles_list = []
    for ur in user_roles_db:
        role = db.query(Role).filter(Role.role_id == ur.role_id).first()
        if role:
            roles_list.append(role.role_name)

    user_groups_db = (
        db.query(UserGroup).filter(UserGroup.user_id == user.user_id).all()
    )
    groups_list = []
    for ug in user_groups_db:
        group = db.query(Group).filter(Group.group_id == ug.group_id).first()
        if group:
            groups_list.append(group.group_name)

    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        account_status=user.account_status,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        roles=roles_list,
        groups=groups_list,
        passkey_credential_id=(
            user.passkey_credential_id.decode("latin1")
            if user.passkey_credential_id
            else None
        ),
    )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_users")),
):
    """Delete user (soft delete by setting status to Disabled)"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    # Prevent self-deletion
    if user.user_id == current_user.user_id:
        raise SelfDeletionForbiddenException()

    # Check if user is the last super admin
    super_admin_role = (
        db.query(Role).filter(Role.role_name == ADMINISTRATOR).first()
    )
    if super_admin_role:
        user_has_super_admin = (
            db.query(UserRole)
            .filter(
                UserRole.user_id == user_id,
                UserRole.role_id == super_admin_role.role_id,
            )
            .first()
        )

        if user_has_super_admin:
            total_super_admins = (
                db.query(UserRole)
                .filter(UserRole.role_id == super_admin_role.role_id)
                .count()
            )
            if total_super_admins <= 1:
                raise LastSuperAdminDeletionForbiddenException()

    user.account_status = "Disabled"
    user.updated_at = int(datetime.now().timestamp())
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "USER_DELETED",
        f"Disabled user {user.username} (ID: {user_id})",
        get_client_ip(request),
    )

    return {"message": "User successfully disabled"}


@router.post("/users/{user_id}/change-password")
async def admin_change_password(
    user_id: int,
    new_password: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_users")),
):
    """Admin force change user password"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    # Validate password strength
    _ = PasswordChange(
        old_password="dummy", new_password=new_password
    )

    # Hash new password
    password_hash, salt = hash_password(new_password)
    user.password_hash = password_hash
    user.password_salt = salt
    user.updated_at = int(datetime.now().timestamp())
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "PASSWORD_CHANGED",
        f"Admin changed password for user {user.username} (ID: {user_id})",
        get_client_ip(request),
    )

    return {"message": "Password changed successfully"}


@router.post("/change-password")
async def change_own_password(
    password_data: PasswordChange,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change own password"""
    # Verify old password
    if not verify_password(
        password_data.old_password,
        current_user.password_hash,
        current_user.password_salt,
    ):
        raise IncorrectCurrentPasswordException()

    # Hash new password
    password_hash, salt = hash_password(password_data.new_password)
    current_user.password_hash = password_hash
    current_user.password_salt = salt
    current_user.updated_at = int(datetime.now().timestamp())
    current_user.force_password_change = False  # Password changed, no longer forced
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "PASSWORD_CHANGED",
        "User changed their own password",
        get_client_ip(request),
    )

    return {"message": "Password changed successfully"}


# --- Role Management Endpoints ---
@router.get("/roles", response_model=List[RoleResponse])
async def get_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Get all roles"""
    roles = db.query(Role).all()
    result = []

    for role in roles:
        # Get role permissions
        role_perms = (
            db.query(RolePermission)
            .filter(RolePermission.role_id == role.role_id)
            .all()
        )
        permissions = []
        for rp in role_perms:
            perm = (
                db.query(Permission)
                .filter(Permission.permission_id == rp.permission_id)
                .first()
            )
            if perm:
                permissions.append(perm.permission_name)

        result.append(
            RoleResponse(
                role_id=role.role_id,
                role_name=role.role_name,
                description=role.description,
                created_at=role.created_at,
                updated_at=role.updated_at,
                permissions=permissions,
            )
        )

    return result


@router.post("/roles", response_model=RoleResponse)
async def create_role(
    role_data: RoleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Create new role"""
    # Check if role already exists
    if db.query(Role).filter(Role.role_name == role_data.role_name).first():
        raise RoleAlreadyExistsException()

    role = Role(
        role_name=role_data.role_name, description=role_data.description
    )
    db.add(role)
    db.commit()
    db.refresh(role)

    log_audit_event(
        db,
        current_user.user_id,
        "ROLE_CREATED",
        f"Created role: {role.role_name}",
        get_client_ip(request),
    )

    return RoleResponse(
        role_id=role.role_id,
        role_name=role.role_name,
        description=role.description,
        created_at=role.created_at,
        updated_at=role.updated_at,
        permissions=[],
    )


@router.post("/roles/{role_id}/permissions/{permission_name}")
async def assign_permission_to_role(
    role_id: int,
    permission_name: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Assign permission to role"""
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise RoleNotFoundException()

    permission = (
        db.query(Permission)
        .filter(Permission.permission_name == permission_name)
        .first()
    )
    if not permission:
        raise PermissionNotFoundException()

    # Check if already assigned
    existing = (
        db.query(RolePermission)
        .filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission.permission_id,
        )
        .first()
    )

    if existing:
        raise PermissionAlreadyAssignedException()

    role_perm = RolePermission(
        role_id=role_id, permission_id=permission.permission_id
    )
    db.add(role_perm)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "PERMISSION_ASSIGNED",
        f"Assigned permission {permission_name} to role {role.role_name}",
        get_client_ip(request),
    )

    return {"message": "Permission assigned to role successfully"}


@router.delete("/roles/{role_id}/permissions/{permission_name}")
async def remove_permission_from_role(
    role_id: int,
    permission_name: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Remove permission from role"""
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise RoleNotFoundException()

    permission = (
        db.query(Permission)
        .filter(Permission.permission_name == permission_name)
        .first()
    )
    if not permission:
        raise PermissionNotFoundException()

    role_perm = (
        db.query(RolePermission)
        .filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission.permission_id,
        )
        .first()
    )

    if not role_perm:
        raise PermissionNotFoundException(detail="Permission not assigned to role")

    db.delete(role_perm)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "PERMISSION_REMOVED",
        f"Removed permission {permission_name} from role {role.role_name}",
        get_client_ip(request),
    )

    return {"message": "Permission removed from role successfully"}


@router.post("/users/{user_id}/roles/{role_id}")
async def assign_role_to_user(
    user_id: int,
    role_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("assign_roles")),
):
    """Assign role to user"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise RoleNotFoundException()

    # Check if already assigned
    existing = (
        db.query(UserRole)
        .filter(UserRole.user_id == user_id, UserRole.role_id == role_id)
        .first()
    )

    if existing:
        raise RoleAlreadyAssignedToUserException()

    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.add(user_role)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "ROLE_ASSIGNED",
        f"Assigned role {role.role_name} to user {user.username}",
        get_client_ip(request),
    )

    return {"message": "Role assigned to user successfully"}


@router.delete("/users/{user_id}/roles/{role_id}")
async def remove_role_from_user(
    user_id: int,
    role_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("assign_roles")),
):
    """Remove role from user"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise RoleNotFoundException()

    # Prevent removing Super Administrator role from last super admin
    if role.role_name == ADMINISTRATOR:
        total_super_admins = (
            db.query(UserRole).filter(UserRole.role_id == role_id).count()
        )
        if total_super_admins <= 1:
            raise LastSuperAdminRoleRemovalForbiddenException()

    user_role = (
        db.query(UserRole)
        .filter(UserRole.user_id == user_id, UserRole.role_id == role_id)
        .first()
    )

    if not user_role:
        raise RoleNotFoundException(detail="Role not assigned to user")

    db.delete(user_role)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "ROLE_REMOVED",
        f"Removed role {role.role_name} from user {user.username}",
        get_client_ip(request),
    )

    return {"message": "Role removed from user successfully"}


# --- Group Management Endpoints ---
@router.get("/groups", response_model=List[GroupResponse])
async def get_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_groups")),
):
    """Get all groups"""
    groups = db.query(Group).all()
    return [
        GroupResponse(
            group_id=group.group_id,
            group_name=group.group_name,
            description=group.description,
            created_at=group.created_at,
            updated_at=group.updated_at,
        )
        for group in groups
    ]


@router.put("/groups/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: int,
    group_update: GroupCreate,  # Re-using GroupCreate for name and description
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_groups")),
):
    """Update group name or description"""
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if not group:
        raise GroupNotFoundException()

    old_name = group.group_name
    old_description = group.description

    if group_update.group_name and group_update.group_name != group.group_name:
        # Check if new group name already exists
        if (
            db.query(Group)
            .filter(
                Group.group_name == group_update.group_name,
                Group.group_id != group_id,
            )
            .first()
        ):
            raise GroupNameAlreadyExistsException()
        group.group_name = group_update.group_name

    if group_update.description is not None:
        group.description = group_update.description

    group.updated_at = int(datetime.now().timestamp())
    db.commit()

    changes = []
    if old_name != group.group_name:
        changes.append(f"name: {old_name} -> {group.group_name}")
    if old_description != group.description:
        changes.append(
            f"description: '{old_description}' -> '{group.description}'"
        )

    if changes:
        log_audit_event(
            db,
            current_user.user_id,
            "GROUP_UPDATED",
            f"Updated group {group.group_name} (ID: {group_id}): {', '.join(changes)}",
            get_client_ip(request),
        )

    return GroupResponse(
        group_id=group.group_id,
        group_name=group.group_name,
        description=group.description,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


@router.delete("/groups/{group_id}")
async def delete_group(
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_groups")),
):
    """Delete a group"""
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if not group:
        raise GroupNotFoundException()

    # Remove all associated UserGroup entries
    db.query(UserGroup).filter(UserGroup.group_id == group_id).delete()

    db.delete(group)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "GROUP_DELETED",
        f"Deleted group: {group.group_name} (ID: {group_id})",
        get_client_ip(request),
    )
    return {"message": "Group deleted successfully"}


@router.delete("/users/{user_id}/groups/{group_id}")
async def remove_user_from_group(
    user_id: int,
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("assign_groups")),
):
    """Remove user from group"""
    user_group = (
        db.query(UserGroup)
        .filter(UserGroup.user_id == user_id, UserGroup.group_id == group_id)
        .first()
    )

    if not user_group:
        raise UserNotInGroupException()

    user = db.query(User).filter(User.user_id == user_id).first()
    group = db.query(Group).filter(Group.group_id == group_id).first()

    db.delete(user_group)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "GROUP_MEMBERSHIP_REMOVED",
        f"Removed user {user.username if user else user_id} from group {group.group_name if group else group_id}",
        get_client_ip(request),
    )
    return {"message": "User removed from group successfully"}


@router.post("/groups", response_model=GroupResponse)
async def create_group(
    group_data: GroupCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_groups")),
):
    """Create new group"""
    if (
        db.query(Group)
        .filter(Group.group_name == group_data.group_name)
        .first()
    ):
        raise GroupAlreadyExistsException()

    group = Group(
        group_name=group_data.group_name, description=group_data.description
    )
    db.add(group)
    db.commit()
    db.refresh(group)

    log_audit_event(
        db,
        current_user.user_id,
        "GROUP_CREATED",
        f"Created group: {group.group_name}",
        get_client_ip(request),
    )

    return GroupResponse(
        group_id=group.group_id,
        group_name=group.group_name,
        description=group.description,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


@router.post("/users/{user_id}/groups/{group_id}")
async def assign_user_to_group(
    user_id: int,
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("assign_groups")),
):
    """Assign user to group"""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise UserNotFoundException()

    group = db.query(Group).filter(Group.group_id == group_id).first()
    if not group:
        raise GroupNotFoundException()

    # Check if already assigned
    existing = (
        db.query(UserGroup)
        .filter(UserGroup.user_id == user_id, UserGroup.group_id == group_id)
        .first()
    )

    if existing:
        raise UserAlreadyAssignedToGroupException()

    user_group = UserGroup(user_id=user_id, group_id=group_id)
    db.add(user_group)
    db.commit()

    log_audit_event(
        db,
        current_user.user_id,
        "GROUP_ASSIGNED",
        f"Assigned user {user.username} to group {group.group_name}",
        get_client_ip(request),
    )

    return {"message": "User assigned to group successfully"}


@router.get("/groups/{group_id}/members", response_model=List[UserResponse])
async def get_group_members(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_groups")),
):
    """Get users who are members of a specific group"""
    group = db.query(Group).filter(Group.group_id == group_id).first()
    if not group:
        raise GroupNotFoundException()

    users_in_group = (
        db.query(User)
        .join(UserGroup, User.user_id == UserGroup.user_id)
        .filter(UserGroup.group_id == group_id)
        .all()
    )

    result = []
    for user in users_in_group:
        # Get user roles (needed for UserResponse model)
        user_roles = (
            db.query(UserRole).filter(UserRole.user_id == user.user_id).all()
        )
        roles = []
        for ur in user_roles:
            role = db.query(Role).filter(Role.role_id == ur.role_id).first()
            if role:
                roles.append(role.role_name)

        # Get user groups (needed for UserResponse model)
        user_groups = (
            db.query(UserGroup).filter(UserGroup.user_id == user.user_id).all()
        )
        groups = []
        for ug in user_groups:
            group_name = (
                db.query(Group).filter(Group.group_id == ug.group_id).first()
            )
            if group_name:
                groups.append(group_name.group_name)

        result.append(
            UserResponse(
                user_id=user.user_id,
                username=user.username,
                account_status=user.account_status,
                last_login_at=user.last_login_at,
                created_at=user.created_at,
                updated_at=user.updated_at,
                roles=roles,
                groups=groups,
                passkey_credential_id=(
                    user.passkey_credential_id.decode("latin1")
                    if user.passkey_credential_id
                    else None
                ),
            )
        )
    return result


# --- Audit Log Endpoints ---
@router.get("/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    description_keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("view_audit_logs")),
):
    """Get audit logs with optional filtering"""
    query = db.query(AuditLog)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if ip_address:
        query = query.filter(AuditLog.ip_address.like(f"%{ip_address}%"))
    if description_keyword:
        query = query.filter(
            AuditLog.event_description.like(f"%{description_keyword}%")
        )

    logs = (
        query.order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    result = []
    for log in logs:
        username = None
        if log.user_id:
            user = db.query(User).filter(User.user_id == log.user_id).first()
            if user:
                username = user.username

        result.append(
            AuditLogResponse(
                log_id=log.log_id,
                user_id=log.user_id,
                username=username,
                event_type=log.event_type,
                event_description=log.event_description,
                ip_address=log.ip_address,
                timestamp=log.timestamp,
            )
        )

    return result


# --- Utility Endpoints ---
@router.get("/permissions")
async def get_permissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: bool = Depends(has_permission("manage_roles")),
):
    """Get all available permissions"""
    permissions = db.query(Permission).all()
    return [
        {"permission_name": p.permission_name, "description": p.description}
        for p in permissions
    ]


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current user information"""
    # Re-fetch roles and groups for the current user to populate UserResponse
    user_roles_db = (
        db.query(UserRole)
        .filter(UserRole.user_id == current_user.user_id)
        .all()
    )
    roles_list = []
    for ur in user_roles_db:
        role = db.query(Role).filter(Role.role_id == ur.role_id).first()
        if role:
            roles_list.append(role.role_name)

    user_groups_db = (
        db.query(UserGroup)
        .filter(UserGroup.user_id == current_user.user_id)
        .all()
    )
    groups_list = []
    for ug in user_groups_db:
        group = db.query(Group).filter(Group.group_id == ug.group_id).first()
        if group:
            groups_list.append(group.group_name)

    return UserResponse(
        user_id=current_user.user_id,
        username=current_user.username,
        account_status=current_user.account_status,
        last_login_at=current_user.last_login_at,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        roles=roles_list,
        groups=groups_list,
        passkey_credential_id=(
            current_user.passkey_credential_id.decode("latin1")
            if current_user.passkey_credential_id
            else None
        ),
    )


@router.post("/emergency-access")
async def emergency_access(
    emergency_code: str, request: Request, db: Session = Depends(get_db)
):
    """Emergency access endpoint - requires special emergency code"""
    # In production, this should be a secure, rotated code stored in environment variables
    EMERGENCY_CODE = os.getenv("EMERGENCY_ACCESS_CODE")

    if not EMERGENCY_CODE or emergency_code != EMERGENCY_CODE:
        log_audit_event(
            db,
            None,
            "EMERGENCY_ACCESS_DENIED",
            "Invalid emergency access attempt",
            get_client_ip(request),
        )
        raise InvalidEmergencyCodeException()

    # Create temporary emergency access token (short-lived)
    access_token_expires = timedelta(minutes=10)  # Very short duration
    access_token = create_access_token(
        data={"sub": "emergency_access", "emergency": True},
        expires_delta=access_token_expires,
    )

    log_audit_event(
        db,
        None,
        "EMERGENCY_ACCESS_GRANTED",
        "Emergency access granted",
        get_client_ip(request),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 600,
    }


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": int(datetime.now().timestamp())}
