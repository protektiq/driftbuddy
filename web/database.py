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


def create_default_permissions(db):
    """Create default permissions for RBAC system"""
    from .models import Permission
    from datetime import datetime

    # Default permissions for different resources
    default_permissions = [
        # Scan permissions
        {"name": "scan:create", "description": "Create new scans", "resource": "scan", "action": "create"},
        {"name": "scan:read", "description": "View scan results", "resource": "scan", "action": "read"},
        {"name": "scan:update", "description": "Update scan configurations", "resource": "scan", "action": "update"},
        {"name": "scan:delete", "description": "Delete scans", "resource": "scan", "action": "delete"},
        {"name": "scan:run", "description": "Execute scans", "resource": "scan", "action": "run"},
        {"name": "scan:export", "description": "Export scan data", "resource": "scan", "action": "export"},
        
        # Report permissions
        {"name": "report:create", "description": "Generate reports", "resource": "report", "action": "create"},
        {"name": "report:read", "description": "View reports", "resource": "report", "action": "read"},
        {"name": "report:export", "description": "Export report data", "resource": "report", "action": "export"},
        {"name": "report:schedule", "description": "Schedule report generation", "resource": "report", "action": "schedule"},
        
        # User permissions
        {"name": "user:create", "description": "Create new users", "resource": "user", "action": "create"},
        {"name": "user:read", "description": "View user information", "resource": "user", "action": "read"},
        {"name": "user:update", "description": "Update user profiles", "resource": "user", "action": "update"},
        {"name": "user:delete", "description": "Delete users", "resource": "user", "action": "delete"},
        {"name": "user:assign_roles", "description": "Assign roles to users", "resource": "user", "action": "assign_roles"},
        
        # Organization permissions
        {"name": "organization:read", "description": "View organization information", "resource": "organization", "action": "read"},
        {"name": "organization:update", "description": "Update organization settings", "resource": "organization", "action": "update"},
        {"name": "organization:manage_users", "description": "Manage organization users", "resource": "organization", "action": "manage_users"},
        {"name": "organization:manage_roles", "description": "Manage organization roles", "resource": "organization", "action": "manage_roles"},
        
        # Cloud permissions
        {"name": "cloud:connect", "description": "Connect cloud accounts", "resource": "cloud", "action": "connect"},
        {"name": "cloud:scan", "description": "Scan cloud infrastructure", "resource": "cloud", "action": "scan"},
        {"name": "cloud:manage_credentials", "description": "Manage cloud credentials", "resource": "cloud", "action": "manage_credentials"},
        
        # Compliance permissions
        {"name": "compliance:read", "description": "View compliance reports", "resource": "compliance", "action": "read"},
        {"name": "compliance:generate", "description": "Generate compliance reports", "resource": "compliance", "action": "generate"},
        {"name": "compliance:export", "description": "Export compliance data", "resource": "compliance", "action": "export"},
        
        # Admin permissions
        {"name": "*:*", "description": "All permissions", "resource": "*", "action": "*"},
    ]

    created_count = 0
    for perm_data in default_permissions:
        existing = db.query(Permission).filter(Permission.name == perm_data["name"]).first()
        if not existing:
            permission = Permission(
                name=perm_data["name"],
                description=perm_data["description"],
                resource=perm_data["resource"],
                action=perm_data["action"],
                conditions={},
                created_at=datetime.utcnow()
            )
            db.add(permission)
            created_count += 1

    if created_count > 0:
        db.commit()
        print(f"✅ Created {created_count} default permissions")


def create_default_roles(db):
    """Create default custom roles for the organization"""
    from .models import CustomRole, Permission
    from datetime import datetime

    # Get default organization
    default_org = create_default_organization(db)
    
    # Get permissions
    permissions = {p.name: p for p in db.query(Permission).all()}
    
    # Default role templates
    default_roles = [
        {
            "name": "Security Analyst",
            "description": "Security analyst with comprehensive access to security features",
            "permissions": [
                "scan:create", "scan:read", "scan:run", "scan:export",
                "report:create", "report:read", "report:export",
                "cloud:connect", "cloud:scan",
                "compliance:read", "compliance:generate", "compliance:export"
            ]
        },
        {
            "name": "Security Manager",
            "description": "Security manager with team management capabilities",
            "permissions": [
                "scan:create", "scan:read", "scan:update", "scan:delete", "scan:run", "scan:export",
                "user:read", "user:update",
                "report:create", "report:read", "report:export", "report:schedule",
                "cloud:connect", "cloud:scan", "cloud:manage_credentials",
                "compliance:read", "compliance:generate", "compliance:export",
                "organization:read", "organization:manage_users"
            ]
        },
        {
            "name": "Compliance Auditor",
            "description": "Compliance auditor with focus on reporting and auditing",
            "permissions": [
                "scan:read", "scan:export",
                "report:create", "report:read", "report:export", "report:schedule",
                "compliance:read", "compliance:generate", "compliance:export"
            ]
        },
        {
            "name": "Developer",
            "description": "Developer with limited access to security features",
            "permissions": ["scan:create", "scan:read", "scan:run", "report:read"]
        },
        {
            "name": "Viewer",
            "description": "Read-only access to security information",
            "permissions": ["scan:read", "report:read"]
        }
    ]

    created_count = 0
    for role_data in default_roles:
        existing = db.query(CustomRole).filter(
            CustomRole.name == role_data["name"],
            CustomRole.organization_id == default_org.id
        ).first()
        
        if not existing:
            role = CustomRole(
                name=role_data["name"],
                description=role_data["description"],
                organization_id=default_org.id,
                is_active=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(role)
            db.flush()  # Get the role ID
            
            # Add permissions
            for perm_name in role_data["permissions"]:
                if perm_name in permissions:
                    role.permissions.append(permissions[perm_name])
            
            created_count += 1

    if created_count > 0:
        db.commit()
        print(f"✅ Created {created_count} default custom roles")


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


def setup_rbac_system(db):
    """Set up the complete RBAC system with default data"""
    try:
        create_default_permissions(db)
        create_default_roles(db)
        print("✅ RBAC system initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize RBAC system: {str(e)}")
        db.rollback()


def setup_compliance_system(db):
    """Set up the complete compliance system with default frameworks"""
    try:
        from .compliance_service import ComplianceService
        compliance_service = ComplianceService()
        compliance_service.create_default_frameworks(db)
        print("✅ Compliance system initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize compliance system: {str(e)}")
        db.rollback()


def setup_ml_analytics_system(db):
    """Set up the complete ML and analytics system with default models"""
    try:
        from .ml_analytics_service import MLAnalyticsService
        ml_service = MLAnalyticsService()
        ml_service.create_default_models(db)
        print("✅ ML and Analytics system initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize ML and Analytics system: {str(e)}")
        db.rollback()


def setup_all_systems(db):
    """Set up all systems (RBAC, Compliance, and ML Analytics)"""
    try:
        setup_rbac_system(db)
        setup_compliance_system(db)
        setup_ml_analytics_system(db)
        print("✅ All systems initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize systems: {str(e)}")
        db.rollback()
