from fastapi import APIRouter, Depends
import keysigning.keycloak as keycloak

router = APIRouter()

@router.get("/user")
async def get_user(user: dict = Depends(keycloak.decode)):
    return user

@router.get("/token")
async def get_token(token: str = Depends(keycloak.oauth2_scheme)):
    return token