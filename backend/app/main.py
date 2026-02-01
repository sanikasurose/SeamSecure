# Load environment variables from .env file
from pathlib import Path
from contextlib import asynccontextmanager
import logging

from dotenv import load_dotenv

# Look for .env in backend/ first, then in parent directory
env_path = Path(__file__).parent.parent / ".env"
if not env_path.exists():
    env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import thread_router, auth_router, gmail_router
from app.core.config import settings, API_VERSION
from app.services.gemini_service import initialize_gemini, get_gemini_status

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Initializes services at startup with timeouts so the server
    always starts cleanly, even if external services fail.
    """
    # Startup
    logger.info("Starting SeamSecure API...")
    
    # Initialize Gemini (with timeout - won't block startup)
    gemini_ready = initialize_gemini()
    if gemini_ready:
        logger.info("Gemini AI analysis: ENABLED")
    else:
        logger.info("Gemini AI analysis: DISABLED (will use rule-based only)")
    
    # Log OAuth status
    if settings.is_oauth_configured:
        logger.info("Google OAuth: CONFIGURED")
    else:
        logger.info("Google OAuth: NOT CONFIGURED (set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)")
    
    logger.info("SeamSecure API ready")
    
    yield
    
    # Shutdown
    logger.info("Shutting down SeamSecure API...")


app = FastAPI(
    title="SeamSecure API",
    description="Email thread security analysis API",
    version=API_VERSION,
    lifespan=lifespan,
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Routers ----------

app.include_router(thread_router)
app.include_router(auth_router)
app.include_router(gmail_router)

# ---------- Root Endpoints ----------


@app.get("/")
def root():
    """Root endpoint with API info and status."""
    gemini_status = get_gemini_status()
    return {
        "message": "SeamSecure backend is running",
        "api_version": API_VERSION,
        "gemini_available": gemini_status["available"],
    }


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "ok"}


@app.get("/status")
def status():
    """Detailed status endpoint showing feature availability."""
    gemini_status = get_gemini_status()
    return {
        "status": "ok",
        "api_version": API_VERSION,
        "environment": settings.environment,
        "features": {
            "rule_based_analysis": True,
            "gemini_ai_analysis": gemini_status["available"],
            "google_oauth": settings.is_oauth_configured,
        },
        "gemini": gemini_status,
    }
