from .endpoint import User
from fastapi import APIRouter
api_router = APIRouter()
api_router.include_router(
    User.router, tags=["user"],
)
