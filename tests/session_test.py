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

    # Provide a get_db function that uses the temporary session local
    def get_temp_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Yield the modified get_db function for the test to use
    yield get_temp_db

    # Teardown: dispose of the engine and remove the temporary database file
    test_engine.dispose()
    os.unlink(temp_db_path)


def test_get_db_yields_session_and_closes(temp_test_db):
    """
    Test that get_db yields a SQLAlchemy session and ensures it's closed afterwards.
    """
    # Use the get_db function provided by the fixture
    gen = temp_test_db()
    db = next(gen)
    assert isinstance(db, Session)
    assert db.is_active is True

    # Perform a simple operation to ensure the session is functional, using the globally available TestItem
    new_item = TestItem(name="Test Item")
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    assert new_item.id is not None
    assert new_item.name == "Test Item"

    # Ensure the session is closed by stopping the generator
    try:
        next(gen)
    except StopIteration:
        pass  # Expected when generator finishes

    assert db.is_active is False
    assert db.closed is True


def test_get_db_exception_handling(temp_test_db):
    """
    Test that get_db correctly closes the session even if an exception occurs.
    """
    gen = temp_test_db()
    db = next(gen)
    assert db.is_active is True

    # Simulate an error within the session context
    with pytest.raises(ValueError):
        try:
            db.add(TestItem(name="Another Item"))
            raise ValueError("Simulated error")
        finally:
            # The 'finally' block in get_db should still execute and close the session
            try:
                next(gen)  # Manually trigger finally block
            except StopIteration:
                pass  # Expected

    assert db.is_active is False
    assert db.closed is True