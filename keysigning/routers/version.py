from fastapi import APIRouter
import keysigning.config as config

router = APIRouter()

@router.get("/version")
async def get_version():
    return {"version": "0.0.1"}


@router.get("/clusters")
async def get_clusters():
    return config.config['clusters']
