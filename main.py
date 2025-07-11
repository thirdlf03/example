from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi_cognito import CognitoToken
import uvicorn
from auth import (
    settings, 
    get_user_info, 
    verify_token_type,
    get_required_auth,
    get_optional_auth,
    require_id_token
)

app = FastAPI(
    title="Progate AWS Backend",
    description="FastAPI backend with AWS Cognito authentication",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """Public endpoint - no authentication required"""
    return {"message": "Hello World", "status": "public"}


@app.get("/health")
def health_check():
    """Health check endpoint - no authentication required"""
    return {"status": "healthy", "service": "progate-backend"}


@app.get("/test")
def test():
    """Public test endpoint"""
    return {"message": "Test endpoint working", "data": {"heko": "hh"}}


@app.get("/protected")
def protected_endpoint(auth: CognitoToken = Depends(get_required_auth())):
    """Protected endpoint - requires valid JWT token"""
    try:
        # Verify token type (accept both id and access tokens)
        user_info = get_user_info(auth)
        
        return {
            "message": "Successfully accessed protected endpoint",
            "user": user_info,
            "timestamp": auth.iat
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/user/profile")
def get_user_profile(auth: CognitoToken = Depends(require_id_token())):
    """Get user profile information - requires ID token"""
    try:
        user_info = get_user_info(auth)
        
        return {
            "profile": {
                "id": user_info["user_id"],
                "email": user_info["email"],
                "username": user_info["username"],
                "preferred_username": user_info["preferred_username"],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/admin")
def admin_endpoint(auth: CognitoToken = Depends(get_required_auth())):
    """Admin endpoint - requires authentication"""
    try:
        user_info = get_user_info(auth)
        
        # Note: Role-based authorization can be implemented here
        # For now, all authenticated users can access this endpoint
        
        return {
            "message": "Admin access granted",
            "user": user_info.get("email", "Unknown"),
            "user_id": user_info["user_id"],
            "admin_data": "Sensitive admin information"
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/optional-auth")
def optional_auth_endpoint(auth: CognitoToken = Depends(get_optional_auth())):
    """Endpoint with optional authentication"""
    if auth:
        user_info = get_user_info(auth)
        return {
            "message": "Hello authenticated user",
            "user": user_info["username"],
            "authenticated": True
        }
    else:
        return {
            "message": "Hello anonymous user",
            "authenticated": False
        }


@app.get("/config")
def get_config():
    """Get application configuration (for debugging)"""
    return {
        "aws_region": settings.aws_region,
        "cognito_configured": bool(
            settings.cognito_user_pool_id != "dummy-pool-id" and 
            settings.cognito_client_id != "dummy-client-id"
        ),
        "environment": settings.environment,
        "user_pool_id": settings.cognito_user_pool_id if settings.cognito_user_pool_id != "dummy-pool-id" else "NOT_CONFIGURED",
        "client_id": settings.cognito_client_id if settings.cognito_client_id != "dummy-client-id" else "NOT_CONFIGURED"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
