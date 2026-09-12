"""SQLAlchemy store: Postgres in prod, SQLite file in dev.

Env:
  DATABASE_URL — e.g. postgresql+psycopg2://user:pass@localhost:5432/mono
                 default: sqlite:///<backend>/mono.db
Tables:
  users(id PK, name, email UNIQUE, pw, created_at ms)
  resumes(id PK, owner_id FK users.id, data JSON (full resume dict),
          created_at ms, updated_at ms)
"""
import os
from pathlib import Path

from sqlalchemy import JSON, BigInteger, Column, ForeignKey, String, create_engine, Index
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

BASE_DIR = Path(__file__).parent
DEFAULT_SQLITE = f"sqlite:///{(BASE_DIR / 'mono.db').as_posix()}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(String(32), primary_key=True)
    name = Column(String(200), nullable=False, default="")
    email = Column(String(320), nullable=False, unique=True, index=True)
    pw = Column(String(255), nullable=False)
    created_at = Column(BigInteger, nullable=False, default=0)
    resumes = relationship("Resume", back_populates="owner", cascade="all, delete-orphan")


class Resume(Base):
    __tablename__ = "resumes"
    id = Column(String(32), primary_key=True)
    owner_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    data = Column(JSON, nullable=False, default=dict)
    created_at = Column(BigInteger, nullable=False, default=0)
    updated_at = Column(BigInteger, nullable=False, default=0)
    owner = relationship("User", back_populates="resumes")


Index("ix_resumes_owner_updated", Resume.owner_id, Resume.updated_at.desc())


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
