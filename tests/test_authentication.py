import os
import sys
import pytest
import time

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add the parent directory to the Python path to allow importing secure_admin_server
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from equus_express.authentication_server import (
    app,
    Base,
    User,
    Role,
    Permission,
    UserRole,
    RolePermission,
    AuditLog,
    hash_password,
    create_access_token,
    MAX_FAILED_ATTEMPTS,
    create_db_and_tables,
    get_db, # Import get_db from the app
)

# Use a test database
TEST_DATABASE_URL = "sqlite:///./test_local_admin.db"
test_engine = create_engine(
    TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)

# Override the get_db dependency for testing
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


# Apply override globally for all tests using this app instance
app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(name="client")
def client_fixture():
    """Returns a TestClient instance with overridden DB dependency."""
    # The dependency override for SessionLocal is handled by override_get_db,
    # which is applied globally to the app for the test session.
    # We do NOT apply app.dependency_overrides inside this fixture because
    # it needs to apply to the `app` object that TestClient uses,
    # and doing it here would not affect `app` at the module level.
    # The setup of app.dependency_overrides = override_get_db is already global for the tests.
    return TestClient(app)


@pytest.fixture(name="db_session")
def db_session_fixture():
    """Provides a clean database session for each test."""
    # Ensure tables are dropped and recreated for each test
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    # Get a session for this fixture to use
    db = TestingSessionLocal()
    try:
        # Call create_db_and_tables with the current session to ensure roles/permissions exist
        create_db_and_tables(db)  # Pass the session explicitly
        db.commit()  # Commit changes made by create_db_and_tables
        yield db
    finally:
        db.close()
    # No need to drop_all again, fixture teardown handles it if used per-test.


@pytest.fixture(name="superadmin_client")
def superadmin_client_fixture(client, db_session):
    """Creates a superadmin user and returns an authenticated client."""
    username = "superadmin"
    password = "SuperAdminPassword!1"

    # Check if superadmin already exists (e.g., from a previous test's setup that failed cleanup)
    superadmin_user = (
        db_session.query(User).filter_by(username=username).first()
    )
    if not superadmin_user:
        # Create superadmin user if they don't exist
        password_hash, password_salt = hash_password(password)
        superadmin_user = User(
            username=username,
            password_hash=password_hash,
            password_salt=password_salt,
            account_status="Active",
            last_login_at=int(time.time()),
        )
        db_session.add(superadmin_user)
        db_session.commit()
        db_session.refresh(superadmin_user)

        # Assign Super Administrator role
        super_admin_role = (
            db_session.query(Role)
            .filter_by(role_name="Super Administrator")
            .first()
        )
        if super_admin_role:
            user_role = UserRole(
                user_id=superadmin_user.user_id,
                role_id=super_admin_role.role_id,
            )
            db_session.add(user_role)
            db_session.commit()
            db_session.refresh(
                superadmin_user
            )  # Refresh user after role assignment

    # Generate a token for the superadmin
    token = create_access_token(data={"sub": superadmin_user.username})

    # Attach the token to the client headers for subsequent requests in tests using this fixture
    client.headers = {"Authorization": f"Bearer {token}"}
    return client


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_register_user_weak_password(superadmin_client, db_session):
    # Use superadmin_client for registration as it requires auth
    response = superadmin_client.post(
        "/register",
        json={
            "username": "weakpassuser",
            "password": "weak",
            "is_super_admin": False,
        },
    )
    assert response.status_code == 422  # Pydantic validation error
    assert (
        "String should have at least 8 characters"
        in response.json()["detail"][0]["msg"]
    )
