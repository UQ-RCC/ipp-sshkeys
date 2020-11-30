import logging

import keysigning.keycloak as keycloak

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from .routers import user, ssh, version

keysigningapi = FastAPI()

# user
keysigningapi.include_router(
    user.router, 
    tags=["user"], 
    dependencies=[Depends(keycloak.decode)], 
    responses={404: {"description": "Not found"}},
)
# job
keysigningapi.include_router(
    ssh.router,
    prefix="/ssh",
    tags=["ssh"],
    dependencies=[Depends(keycloak.decode)],
    responses={404: {"description": "Not found"}},
)
# miscs
keysigningapi.include_router(
    version.router, 
    tags=["miscs"], 
    responses={404: {"description": "Not found"}},
)

