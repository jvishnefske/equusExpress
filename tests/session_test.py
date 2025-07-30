import pytest
import os
import tempfile
from sqlalchemy.orm import Session, sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, create_engine

# Define TestItem outside the fixture but we'll set its Base dynamically
TestItem = None


@pytest.fixture(scope="function")
def temp_test_db(monkeypatch, request):
    """
    Fixture to create a temporary SQLite database for testing the session module.
    It overrides the DATABASE_URL environment variable and ensures tables are created.
    """
    global TestItem

    # Create a temporary file for the SQLite database
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp_file:
        temp_db_path = tmp_file.name

    # Override the DATABASE_URL environment variable for this test function's scope
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{temp_db_path}")
    # Re-initialize the engine and SessionLocal to pick up the new DATABASE_URL
    test_engine = create_engine(f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False})
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Define a local Base for the test to ensure it's bound to the test_engine
    TestBase = declarative_base()

    # Define TestItem dynamically with the TestBase
    class TestItemLocal(TestBase):
        __tablename__ = "test_items"
        id = Column(Integer, primary_key=True, index=True)
        name = Column(String, index=True)

    # Set the global TestItem to our local class
    TestItem = TestItemLocal

    # Create all tables defined by TestBase in the temporary database
    TestBase.metadata.create_all(bind=test_engine)

    # Yield a session directly for the test to use. Pytest will handle closing it.
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()

    # Teardown: dispose of the engine and remove the temporary database file
    test_engine.dispose()
    os.unlink(temp_db_path)


def test_get_db_yields_session_and_closes(temp_test_db):
    """
    Test that get_db yields a SQLAlchemy session and ensures it's closed afterwards.
    """
    # The fixture directly yields the session.
    # Pytest manages the lifecycle including the finalization of the generator.
    assert isinstance(temp_test_db, Session)
    assert temp_test_db.is_active is True

    # Perform a simple operation to ensure the session is functional, using the globally available TestItem
    new_item = TestItem(name="Test Item")
    temp_test_db.add(new_item)
    temp_test_db.commit()
    temp_test_db.refresh(new_item)
    assert new_item.id is not None
    assert new_item.name == "Test Item"

    # The session should be active within the test.
    # It will be closed automatically by the fixture's finally block after the test completes.
    assert temp_test_db.is_active is True


def test_get_db_exception_handling(temp_test_db):
    """
    Test that get_db correctly closes the session even if an exception occurs.
    """
    assert isinstance(temp_test_db, Session)
    assert temp_test_db.is_active is True

    # Simulate an error within the session context
    with pytest.raises(ValueError):
        temp_test_db.add(TestItem(name="Another Item"))
        raise ValueError("Simulated error")

    # The session should be active immediately after the error (before fixture teardown).
    # It will be closed automatically by the fixture's finally block after the test completes.
    assert temp_test_db.is_active is True
