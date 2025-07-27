"""
Database connection and session management for DriftBuddy Web Interface
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./driftbuddy.db")

# Create database engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models
Base = declarative_base()


def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    from .models import Base

    Base.metadata.create_all(bind=engine)


def create_default_organization(db):
    """Create default organization if it doesn't exist"""
    from .models import Organization

    # Check if default organization exists
    default_org = db.query(Organization).filter(Organization.slug == "default").first()

    if not default_org:
        default_org = Organization(name="Default Organization", slug="default", settings={})
        db.add(default_org)
        db.commit()
        db.refresh(default_org)

    return default_org


def create_default_admin(db):
    """Create default admin user if it doesn't exist"""
    from .auth import get_password_hash
    from .models import User, UserRole

    # Check if admin user exists
    admin_user = db.query(User).filter(User.email == "admin@driftbuddy.com").first()

    if not admin_user:
        default_org = create_default_organization(db)

        admin_user = User(
            email="admin@driftbuddy.com",
            username="admin",
            hashed_password=get_password_hash("admin123"),
            role=UserRole.ADMIN.value,
            organization_id=default_org.id,
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

    return admin_user
