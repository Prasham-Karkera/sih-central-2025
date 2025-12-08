# setup.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

# Import Base from separate file to avoid circular imports
from src.db.base import Base

# Ensure folder exists
os.makedirs("collected_logs", exist_ok=True)

DB_PATH = "collected_logs/ironclad_logs.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},   # Needed for SQLite multithreading
    echo=False
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def init_db():
    """Initialize database - create all tables."""
    # Import models here to register them with Base
    # This lazy import avoids circular dependency issues
    import src.db.models  # noqa: F401
    
    print(f"[DB] Creating database at {DB_PATH}")
    Base.metadata.create_all(bind=engine)
    print("[DB] ✅ All tables created successfully!")


def get_db():
    """FastAPI dependency or general DB helper."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    init_db()

