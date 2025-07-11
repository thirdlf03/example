
"""AWS Cognito JWT Authentication module for FastAPI using PyJWT"""
import json
import time
from typing import Dict, Optional, Any
from functools import lru_cache
from urllib.parse import urljoin

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, status, Depends, Request
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with Cognito configuration"""
    
    # AWS Configuration
    aws_region: str = "ap-northeast-1"
    
    # Cognito Configuration
    cognito_user_pool_id: str = "dummy-pool-id"
    cognito_client_id: str = "dummy-client-id"
    
    # Application Configuration
    environment: str = "development"
    cors_origins: str = "http://localhost:5173,http://localhost:3000,https://thirdlf03.com"
    
    model_config = {
        'env_file': '.env',
        'env_file_encoding': 'utf-8',
        'case_sensitive': False,
    }


class CognitoUser(BaseModel):
    """User information extracted from Cognito JWT token"""
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    cognito_username: Optional[str] = None
    preferred_username: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    name: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None
    token_use: str
    client_id: str
    exp: int
    iat: int
    iss: str
    aud: Optional[str] = None
    auth_time: Optional[int] = None
    custom_attributes: Dict[str, Any] = {}


class CognitoJWTAuth:
    """AWS Cognito JWT Authentication handler"""
    
    def __init__(self, user_pool_id: str, client_id: str, region: str = "ap-northeast-1"):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.region = region
        self.issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        self.jwks_url = f"{self.issuer}/.well-known/jwks.json"
        self._jwks_cache = {}
        self._jwks_cache_time = 0
        self._jwks_cache_ttl = 300  # 5 minutes
    
    @lru_cache(maxsize=32)
    def _get_jwks(self) -> Dict[str, Any]:
        """Fetch JWKS from Cognito with caching"""
        current_time = time.time()
        if (current_time - self._jwks_cache_time) < self._jwks_cache_ttl and self._jwks_cache:
            return self._jwks_cache
        
        try:
            response = requests.get(self.jwks_url, timeout=10)
            response.raise_for_status()
            self._jwks_cache = response.json()
            self._jwks_cache_time = current_time
            return self._jwks_cache
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to fetch JWKS from Cognito: {str(e)}"
            )
    
    def _get_public_key(self, kid: str) -> str:
        """Get public key for given key ID"""
        jwks = self._get_jwks()
        
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                # Convert JWK to PEM format
                if key.get("kty") == "RSA":
                    n = self._base64url_decode(key["n"])
                    e = self._base64url_decode(key["e"])
                    
                    # Create RSA public key
                    public_numbers = rsa.RSAPublicNumbers(
                        int.from_bytes(e, byteorder='big'),
                        int.from_bytes(n, byteorder='big')
                    )
                    public_key = public_numbers.public_key()
                    
                    # Convert to PEM format
                    pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    return pem.decode('utf-8')
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to find matching public key for kid: {kid}"
        )
    
    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url encoded data"""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        return jwt.utils.base64url_decode(data)
    
    def verify_token(self, token: str) -> CognitoUser:
        """Verify and decode JWT token"""
        try:
            # Decode token header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token header missing kid"
                )
            
            # Get public key
            public_key = self._get_public_key(kid)
            
            # Verify and decode token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_nbf": False,
                }
            )
            
            # Extract custom attributes
            custom_attrs = {}
            for key, value in payload.items():
                if key.startswith("custom:"):
                    custom_attrs[key] = value
            
            # Create CognitoUser object
            user = CognitoUser(
                sub=payload.get("sub"),
                email=payload.get("email"),
                email_verified=payload.get("email_verified"),
                cognito_username=payload.get("cognito:username"),
                preferred_username=payload.get("preferred_username"),
                given_name=payload.get("given_name"),
                family_name=payload.get("family_name"),
                name=payload.get("name"),
                phone_number=payload.get("phone_number"),
                phone_number_verified=payload.get("phone_number_verified"),
                token_use=payload.get("token_use"),
                client_id=payload.get("client_id", payload.get("aud")),
                exp=payload.get("exp"),
                iat=payload.get("iat"),
                iss=payload.get("iss"),
                aud=payload.get("aud"),
                auth_time=payload.get("auth_time"),
                custom_attributes=custom_attrs
            )
            
            return user
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token verification failed: {str(e)}"
            )


# Initialize settings
settings = Settings()

# Initialize Cognito authentication only if real credentials are provided
if (settings.cognito_user_pool_id != "dummy-pool-id" and 
    settings.cognito_client_id != "dummy-client-id" and
    not settings.cognito_user_pool_id.startswith("your-") and
    not settings.cognito_client_id.startswith("your-")):
    try:
        cognito_auth = CognitoJWTAuth(
            user_pool_id=settings.cognito_user_pool_id,
            client_id=settings.cognito_client_id,
            region=settings.aws_region
        )
        print(f"✅ Cognito authentication initialized for pool: {settings.cognito_user_pool_id}")
    except Exception as e:
        print(f"❌ Failed to initialize Cognito authentication: {e}")
        cognito_auth = None
else:
    print("⚠️  Using dummy Cognito settings. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID for authentication.")
    cognito_auth = None


def extract_token_from_request(request: Request) -> Optional[str]:
    """
    Extract JWT token from request headers
    
    Args:
        request: FastAPI request object
        
    Returns:
        JWT token string or None if not found
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    
    if not auth_header.startswith("Bearer "):
        return None
    
    return auth_header.split(" ", 1)[1]


def get_user_info(auth: CognitoUser) -> Dict[str, Any]:
    """
    Extract user information from Cognito user object
    
    Args:
        auth: Cognito user object from dependency injection
        
    Returns:
        Dictionary containing user information
    """
    return {
        "user_id": auth.sub,
        "email": auth.email,
        "email_verified": auth.email_verified,
        "username": auth.cognito_username or auth.sub,
        "preferred_username": auth.preferred_username,
        "given_name": auth.given_name,
        "family_name": auth.family_name,
        "name": auth.name,
        "phone_number": auth.phone_number,
        "phone_number_verified": auth.phone_number_verified,
        "token_use": auth.token_use,
        "client_id": auth.client_id,
        "exp": auth.exp,
        "iat": auth.iat,
        "iss": auth.iss,
        "aud": auth.aud,
        "auth_time": auth.auth_time,
        "custom_attributes": auth.custom_attributes,
    }


def verify_token_type(auth: CognitoUser, required_token_use: str = "id") -> bool:
    """
    Verify token type (id or access token)
    
    Args:
        auth: Cognito user object
        required_token_use: Required token use ("id" or "access")
        
    Returns:
        True if token type is valid, raises HTTPException otherwise
    """
    if auth.token_use != required_token_use:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token type. Expected '{required_token_use}', got '{auth.token_use}'"
        )
    
    return True


def get_optional_auth():
    """
    Dependency for optional authentication
    Returns None if no token is provided, CognitoUser if valid token is provided
    """
    def optional_auth_dependency(request: Request) -> Optional[CognitoUser]:
        if cognito_auth is None:
            return None
        
        token = extract_token_from_request(request)
        if not token:
            return None
        
        try:
            return cognito_auth.verify_token(token)
        except HTTPException:
            return None
    
    return optional_auth_dependency


def get_required_auth():
    """
    Dependency for required authentication
    Raises 401 if no valid token is provided
    """
    def required_auth_dependency(request: Request) -> CognitoUser:
        if cognito_auth is None:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authentication not configured. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables."
            )
        
        token = extract_token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header missing or invalid"
            )
        
        return cognito_auth.verify_token(token)
    
    return required_auth_dependency


# Convenience functions for different authentication requirements
def require_id_token():
    """Dependency that requires a valid ID token"""
    def id_token_dependency(request: Request) -> CognitoUser:
        if cognito_auth is None:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authentication not configured. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables."
            )
        
        token = extract_token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header missing or invalid"
            )
        
        user = cognito_auth.verify_token(token)
        verify_token_type(user, "id")
        return user
    
    return id_token_dependency


def require_access_token():
    """Dependency that requires a valid access token"""
    def access_token_dependency(request: Request) -> CognitoUser:
        if cognito_auth is None:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authentication not configured. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables."
            )
        
        token = extract_token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header missing or invalid"
            )
        
        user = cognito_auth.verify_token(token)
        verify_token_type(user, "access")
        return user
    
    return access_token_dependency


# Shortcut dependencies for common use cases
OptionalAuth = Depends(get_optional_auth())
RequiredAuth = Depends(get_required_auth())
RequireIdToken = Depends(require_id_token())
RequireAccessToken = Depends(require_access_token())