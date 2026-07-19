import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Hosted deployments set DATABASE_URL (e.g. a Neon Postgres connection string);
# local development falls back to SQLite.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./seclog.db")
if DATABASE_URL.startswith("postgres://"):
    # Some providers hand out the legacy scheme SQLAlchemy no longer accepts.
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
