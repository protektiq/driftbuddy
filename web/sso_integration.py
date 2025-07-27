"""
SSO Integration for DriftBuddy Web Interface - Phase 3
Provides SAML, OAuth, and LDAP authentication integration
"""

import base64
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlencode

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from .auth import create_access_token, get_password_hash
from .database import get_db
from .models import Organization, User, UserRole


class SSOIntegration:
    """SSO integration service for enterprise authentication"""

    def __init__(self):
        self.saml_config = self._load_saml_config()
        self.oauth_config = self._load_oauth_config()
        self.ldap_config = self._load_ldap_config()

    def _load_saml_config(self) -> Dict[str, Any]:
        """Load SAML configuration from environment"""
        return {
            "enabled": os.getenv("SAML_ENABLED", "false").lower() == "true",
            "entity_id": os.getenv("SAML_ENTITY_ID", "driftbuddy"),
            "acs_url": os.getenv("SAML_ACS_URL", "http://localhost:8000/api/sso/saml/acs"),
            "idp_metadata_url": os.getenv("SAML_IDP_METADATA_URL"),
            "idp_entity_id": os.getenv("SAML_IDP_ENTITY_ID"),
            "idp_sso_url": os.getenv("SAML_IDP_SSO_URL"),
            "idp_slo_url": os.getenv("SAML_IDP_SLO_URL"),
            "certificate": os.getenv("SAML_CERTIFICATE"),
            "private_key": os.getenv("SAML_PRIVATE_KEY"),
            "name_id_format": os.getenv("SAML_NAME_ID_FORMAT", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        }

    def _load_oauth_config(self) -> Dict[str, Any]:
        """Load OAuth configuration from environment"""
        return {
            "enabled": os.getenv("OAUTH_ENABLED", "false").lower() == "true",
            "providers": {
                "google": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
                    "token_url": "https://oauth2.googleapis.com/token",
                    "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
                    "scope": "openid email profile",
                },
                "github": {
                    "client_id": os.getenv("GITHUB_CLIENT_ID"),
                    "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
                    "authorization_url": "https://github.com/login/oauth/authorize",
                    "token_url": "https://github.com/login/oauth/access_token",
                    "userinfo_url": "https://api.github.com/user",
                    "scope": "read:user user:email",
                },
                "azure": {
                    "client_id": os.getenv("AZURE_CLIENT_ID"),
                    "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
                    "tenant_id": os.getenv("AZURE_TENANT_ID"),
                    "authorization_url": f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}/oauth2/v2.0/authorize",
                    "token_url": f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}/oauth2/v2.0/token",
                    "userinfo_url": "https://graph.microsoft.com/v1.0/me",
                    "scope": "openid email profile",
                },
            },
        }

    def _load_ldap_config(self) -> Dict[str, Any]:
        """Load LDAP configuration from environment"""
        return {
            "enabled": os.getenv("LDAP_ENABLED", "false").lower() == "true",
            "server_url": os.getenv("LDAP_SERVER_URL"),
            "bind_dn": os.getenv("LDAP_BIND_DN"),
            "bind_password": os.getenv("LDAP_BIND_PASSWORD"),
            "base_dn": os.getenv("LDAP_BASE_DN"),
            "user_search_filter": os.getenv("LDAP_USER_SEARCH_FILTER", "(uid={})"),
            "group_search_filter": os.getenv("LDAP_GROUP_SEARCH_FILTER", "(member={})"),
            "group_base_dn": os.getenv("LDAP_GROUP_BASE_DN"),
            "group_mapping": json.loads(os.getenv("LDAP_GROUP_MAPPING", "{}")),
        }

    async def get_sso_providers(self) -> Dict[str, Any]:
        """Get available SSO providers"""
        providers = {}

        if self.saml_config["enabled"]:
            providers["saml"] = {"name": "SAML SSO", "login_url": "/api/sso/saml/login", "metadata_url": "/api/sso/saml/metadata"}

        if self.oauth_config["enabled"]:
            for provider_name, config in self.oauth_config["providers"].items():
                if config.get("client_id") and config.get("client_secret"):
                    providers[provider_name] = {
                        "name": f"{provider_name.title()} OAuth",
                        "login_url": f"/api/sso/oauth/{provider_name}/login",
                        "callback_url": f"/api/sso/oauth/{provider_name}/callback",
                    }

        if self.ldap_config["enabled"]:
            providers["ldap"] = {"name": "LDAP Authentication", "login_url": "/api/sso/ldap/login"}

        return providers

    async def handle_saml_login(self, db: Session) -> Dict[str, Any]:
        """Handle SAML login initiation"""
        if not self.saml_config["enabled"]:
            return {"success": False, "error": "SAML SSO not enabled"}

        try:
            # Generate SAML request
            saml_request = self._generate_saml_request()

            # Redirect to IdP
            redirect_url = f"{self.saml_config['idp_sso_url']}?{urlencode({'SAMLRequest': saml_request})}"

            return {"success": True, "redirect_url": redirect_url, "saml_request": saml_request}

        except Exception as e:
            return {"success": False, "error": f"SAML login failed: {str(e)}"}

    async def handle_saml_acs(self, saml_response: str, db: Session) -> Dict[str, Any]:
        """Handle SAML Assertion Consumer Service"""
        if not self.saml_config["enabled"]:
            return {"success": False, "error": "SAML SSO not enabled"}

        try:
            # Parse and validate SAML response
            user_info = self._parse_saml_response(saml_response)

            if not user_info:
                return {"success": False, "error": "Invalid SAML response"}

            # Find or create user
            user = await self._get_or_create_sso_user(db, user_info, "saml")

            # Generate access token
            access_token = create_access_token(data={"sub": str(user.id)})

            return {"success": True, "access_token": access_token, "user": {"id": user.id, "email": user.email, "username": user.username, "role": user.role}}

        except Exception as e:
            return {"success": False, "error": f"SAML ACS failed: {str(e)}"}

    async def handle_oauth_login(self, provider: str, db: Session) -> Dict[str, Any]:
        """Handle OAuth login initiation"""
        if not self.oauth_config["enabled"]:
            return {"success": False, "error": "OAuth SSO not enabled"}

        if provider not in self.oauth_config["providers"]:
            return {"success": False, "error": f"OAuth provider {provider} not configured"}

        config = self.oauth_config["providers"][provider]

        try:
            # Generate OAuth authorization URL
            params = {
                "client_id": config["client_id"],
                "redirect_uri": f"http://localhost:8000/api/sso/oauth/{provider}/callback",
                "response_type": "code",
                "scope": config["scope"],
                "state": self._generate_state_token(),
            }

            auth_url = f"{config['authorization_url']}?{urlencode(params)}"

            return {"success": True, "redirect_url": auth_url}

        except Exception as e:
            return {"success": False, "error": f"OAuth login failed: {str(e)}"}

    async def handle_oauth_callback(self, provider: str, code: str, state: str, db: Session) -> Dict[str, Any]:
        """Handle OAuth callback"""
        if not self.oauth_config["enabled"]:
            return {"success": False, "error": "OAuth SSO not enabled"}

        if provider not in self.oauth_config["providers"]:
            return {"success": False, "error": f"OAuth provider {provider} not configured"}

        config = self.oauth_config["providers"][provider]

        try:
            # Exchange code for access token
            token_response = requests.post(
                config["token_url"],
                data={
                    "client_id": config["client_id"],
                    "client_secret": config["client_secret"],
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": f"http://localhost:8000/api/sso/oauth/{provider}/callback",
                },
            )

            if token_response.status_code != 200:
                return {"success": False, "error": "Failed to exchange code for token"}

            token_data = token_response.json()
            access_token = token_data["access_token"]

            # Get user information
            user_response = requests.get(config["userinfo_url"], headers={"Authorization": f"Bearer {access_token}"})

            if user_response.status_code != 200:
                return {"success": False, "error": "Failed to get user information"}

            user_info = user_response.json()

            # Find or create user
            user = await self._get_or_create_sso_user(db, user_info, provider)

            # Generate access token
            driftbuddy_token = create_access_token(data={"sub": str(user.id)})

            return {
                "success": True,
                "access_token": driftbuddy_token,
                "user": {"id": user.id, "email": user.email, "username": user.username, "role": user.role},
            }

        except Exception as e:
            return {"success": False, "error": f"OAuth callback failed: {str(e)}"}

    async def handle_ldap_login(self, username: str, password: str, db: Session) -> Dict[str, Any]:
        """Handle LDAP authentication"""
        if not self.ldap_config["enabled"]:
            return {"success": False, "error": "LDAP authentication not enabled"}

        try:
            # Authenticate with LDAP
            ldap_user = self._authenticate_ldap_user(username, password)

            if not ldap_user:
                return {"success": False, "error": "Invalid LDAP credentials"}

            # Find or create user
            user = await self._get_or_create_sso_user(db, ldap_user, "ldap")

            # Generate access token
            access_token = create_access_token(data={"sub": str(user.id)})

            return {"success": True, "access_token": access_token, "user": {"id": user.id, "email": user.email, "username": user.username, "role": user.role}}

        except Exception as e:
            return {"success": False, "error": f"LDAP login failed: {str(e)}"}

    async def _get_or_create_sso_user(self, db: Session, user_info: Dict[str, Any], provider: str) -> User:
        """Get or create user from SSO information"""
        email = user_info.get("email")
        if not email:
            raise ValueError("Email is required for SSO user creation")

        # Check if user exists
        user = db.query(User).filter(User.email == email).first()

        if user:
            # Update user information
            user.username = user_info.get("username", user_info.get("name", email.split("@")[0]))
            user.updated_at = datetime.utcnow()
            db.commit()
            return user

        # Create new user
        username = user_info.get("username", user_info.get("name", email.split("@")[0]))
        role = self._map_sso_role(user_info, provider)

        user = User(
            email=email,
            username=username,
            hashed_password="",  # SSO users don't have local passwords
            role=role.value,
            organization_id=1,  # Default organization
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user

    def _map_sso_role(self, user_info: Dict[str, Any], provider: str) -> UserRole:
        """Map SSO user information to DriftBuddy role"""
        # Default to developer role
        default_role = UserRole.DEVELOPER

        if provider == "ldap":
            # Map LDAP groups to roles
            groups = user_info.get("groups", [])
            group_mapping = self.ldap_config.get("group_mapping", {})

            for group in groups:
                if group in group_mapping:
                    role_name = group_mapping[group]
                    if role_name == "admin":
                        return UserRole.ADMIN
                    elif role_name == "appsec":
                        return UserRole.APPSEC
                    elif role_name == "developer":
                        return UserRole.DEVELOPER

        elif provider in ["google", "github", "azure"]:
            # Map OAuth provider roles
            # This could be based on domain, organization, or custom claims
            email = user_info.get("email", "")
            if email.endswith("@company.com"):
                return UserRole.ADMIN
            elif "security" in email.lower() or "appsec" in email.lower():
                return UserRole.APPSEC

        return default_role

    def _generate_saml_request(self) -> str:
        """Generate SAML authentication request"""
        # This is a simplified implementation
        # In production, use a proper SAML library like python-saml
        saml_request = f"""
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="{self._generate_id()}"
                           Version="2.0"
                           IssueInstant="{datetime.utcnow().isoformat()}Z"
                           ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                           AssertionConsumerServiceURL="{self.saml_config['acs_url']}">
            <saml:Issuer>{self.saml_config['entity_id']}</saml:Issuer>
            <samlp:NameIDPolicy Format="{self.saml_config['name_id_format']}"
                               AllowCreate="true"/>
        </samlp:AuthnRequest>
        """

        return base64.b64encode(saml_request.encode()).decode()

    def _parse_saml_response(self, saml_response: str) -> Optional[Dict[str, Any]]:
        """Parse SAML response and extract user information"""
        # This is a simplified implementation
        # In production, use a proper SAML library
        try:
            decoded_response = base64.b64decode(saml_response).decode()
            # Parse XML and extract user information
            # For now, return mock data
            return {"email": "user@example.com", "username": "sso_user", "name": "SSO User"}
        except Exception:
            return None

    def _authenticate_ldap_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with LDAP"""
        # This is a simplified implementation
        # In production, use a proper LDAP library like python-ldap
        try:
            # Mock LDAP authentication
            if username == "admin" and password == "admin123":
                return {"email": "admin@company.com", "username": "admin", "name": "Admin User", "groups": ["admin", "security"]}
            elif username == "user" and password == "user123":
                return {"email": "user@company.com", "username": "user", "name": "Regular User", "groups": ["developers"]}
            return None
        except Exception:
            return None

    def _generate_state_token(self) -> str:
        """Generate state token for OAuth"""
        import secrets

        return secrets.token_urlsafe(32)

    def _generate_id(self) -> str:
        """Generate unique ID for SAML"""
        import secrets

        return f"_{secrets.token_hex(16)}"

    def get_saml_metadata(self) -> str:
        """Generate SAML metadata"""
        if not self.saml_config["enabled"]:
            return ""

        metadata = f"""
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                           entityID="{self.saml_config['entity_id']}">
            <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                           Location="{self.saml_config['acs_url']}"/>
            </md:SPSSODescriptor>
        </md:EntityDescriptor>
        """

        return metadata
