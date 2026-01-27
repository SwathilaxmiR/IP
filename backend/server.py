# VulnScan API Server
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from config import get_settings, Database
from routes import (
    auth_router,
    repository_router,
    vulnerability_router,
    scan_router,
    ai_pattern_router,
    pull_request_router,
    activity_router,
    dashboard_router
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await Database.connect_db()
    logger.info('Application started')
    yield
    # Shutdown
    await Database.close_db()
    logger.info('Application shutdown')

app = FastAPI(
    title='VulnScan API',
    description='AI-powered vulnerability scanning platform',
    version='1.0.0',
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(','),
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# API Router
api_router = APIRouter(prefix='/api')

# Include all route modules
api_router.include_router(auth_router)
api_router.include_router(repository_router)
api_router.include_router(vulnerability_router)
api_router.include_router(scan_router)
api_router.include_router(ai_pattern_router)
api_router.include_router(pull_request_router)
api_router.include_router(activity_router)
api_router.include_router(dashboard_router)

# Include API router
app.include_router(api_router)

@app.get('/')
async def root():
    return {'message': 'VulnScan API v1.0.0', 'status': 'operational'}

@app.get('/health')
async def health():
    return {'status': 'healthy'}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", reload=True)
