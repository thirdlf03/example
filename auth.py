"""
AWS Cognito JWT Authentication module for FastAPI using fastapi-cognito
"""
from typing import Dict, Optional
from fastapi import HTTPException, status, Depends
from pydantic_settings import BaseSettings
from fastapi_cognito import CognitoAuth, CognitoSettings, CognitoToken


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


# Initialize settings
settings = Settings()

# Initialize Cognito authentication only if real credentials are provided
if (settings.cognito_user_pool_id != "dummy-pool-id" and 
    settings.cognito_client_id != "dummy-client-id" and
    not settings.cognito_user_pool_id.startswith("your-") and
    not settings.cognito_client_id.startswith("your-")):
    try:
        cognito_settings = CognitoSettings(
            region=settings.aws_region,
            userpoolid=settings.cognito_user_pool_id,
            app_client_id=settings.cognito_client_id,
            check_expiration=True,
            jwt_header_name="Authorization",
            jwt_header_prefix="Bearer",
            userpools={
                settings.cognito_user_pool_id: settings.cognito_client_id
            }
        )
        cognito_auth = CognitoAuth(settings=cognito_settings)
        print(f"✅ Cognito authentication initialized for pool: {settings.cognito_user_pool_id}")
    except Exception as e:
        print(f"❌ Failed to initialize Cognito authentication: {e}")
        cognito_auth = None
else:
    print("⚠️  Using dummy Cognito settings. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID for authentication.")
    cognito_auth = None


def get_user_info(auth: CognitoToken) -> Dict:
    """
    Extract user information from Cognito token
    
    Args:
        auth: Cognito JWT token from dependency injection
        
    Returns:
        Dictionary containing user information
    """
    try:
        return {
            "user_id": auth.sub,
            "email": getattr(auth, 'email', None),
            "username": getattr(auth, 'cognito:username', auth.sub),
            "preferred_username": getattr(auth, 'preferred_username', None),
            "token_use": auth.token_use,
            "client_id": auth.client_id,
            "exp": auth.exp,
            "iat": auth.iat,
            "iss": auth.iss,
            "aud": getattr(auth, 'aud', None),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to extract user info from token: {str(e)}"
        )


def verify_token_type(auth: CognitoToken, required_token_use: str = "id") -> bool:
    """
    Verify token type (id or access token)
    
    Args:
        auth: Cognito JWT token
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
    Returns None if no token is provided, CognitoToken if valid token is provided
    """
    if cognito_auth is None:
        return lambda: None
    return cognito_auth.auth_optional


def get_required_auth():
    """
    Dependency for required authentication
    Raises 401 if no valid token is provided
    """
    if cognito_auth is None:
        def dummy_auth():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authentication not configured. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables."
            )
        return dummy_auth
    return cognito_auth.auth_required


# Convenience functions for different authentication requirements
def require_id_token():
    """Dependency that requires a valid ID token"""
    if cognito_auth is None:
        def dummy_auth():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authentication not configured. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables."
            )
        return dummy_auth
    
    def verify_id_token(auth: CognitoToken = Depends(cognito_auth.auth_required)):
        verify_token_type(auth, "id")
        return auth
    return verify_id_token


def require_access_token():
    """Dependency that requires a valid access token"""
    if cognito_auth is None:
        def dummy_auth():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authentication not configured. Set COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID environment variables."
            )
        return dummy_auth
    
    def verify_access_token(auth: CognitoToken = Depends(cognito_auth.auth_required)):
        verify_token_type(auth, "access")
        return auth
    return verify_access_token