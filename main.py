from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional, List
import jwt
import datetime
import uuid
import os
from dotenv import load_dotenv 

# Load environment variables (for production, store secrets in .env)
load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-256-bit-secret")  # Use a strong secret key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="JWT Generator API", description="A simple API to generate dummy JWT tokens")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class TokenRequest(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None
    custom_claims: Optional[dict] = None

class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/generate-token", response_model=Token)
async def generate_token(request: TokenRequest):
    """
    Generate a dummy JWT token similar to what Azure AD would issue.
    
    This is for demonstration purposes only and should not be used in production
    without proper security measures.
    """
    # Current time for issued at claim
    now = datetime.datetime.utcnow()
    
    # Create payload with claims similar to Azure AD
    payload = {
        # Standard JWT claims
        "iss": "https://login.microsoftonline.com/dummy-tenant-id/v2.0",
        "sub": str(uuid.uuid4()),
        "aud": "api://dummy-app-id",
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),
        
        # Azure AD specific claims
        "tid": "87654321-dcba-0fe4-dcba-0987654321ab",  # Tenant ID
        "oid": str(uuid.uuid4()),  # Object ID
        "upn": request.email or f"{request.username}@example.com",
        "preferred_username": request.email or f"{request.username}@example.com",
        "name": request.full_name or request.username,
        "ver": "2.0"
    }
    
    # Add optional claims if provided
    if request.roles:
        payload["roles"] = request.roles
    
    if request.groups:
        payload["groups"] = request.groups
    
    # Add any custom claims
    if request.custom_claims:
        for key, value in request.custom_claims.items():
            # Don't override standard claims
            if key not in payload:
                payload[key] = value
    
    # Encode JWT
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/")
async def root():
    return {"message": "JWT Generator API is running. Use POST /generate-token to get a token."}

@app.get("/verify-token")
async def verify_token(token: str = Depends(oauth2_scheme)):
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"valid": True, "payload": payload}
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)