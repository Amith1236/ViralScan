"""Health check controller
 - To be used by Docker, load balancers, and CI.
 """
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    version: str = "1.0.0"


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="ok")
