# Name: config.py
# Description: Application configuration and environment variable management
# Date: 2026-02-01

import os
from typing import Optional
from functools import lru_cache


# =============================================================================
# API VERSION - Single source of truth
# =============================================================================
# Versioning policy (Semantic Versioning):
#   - MAJOR: Breaking changes to request/response schemas
#   - MINOR: New features, new optional fields (backward compatible)
#   - PATCH: Bug fixes, documentation updates
#
# Version history:
#   1.0.0 - Initial release with rule-based analysis
#   1.1.0 - Added Gemini AI analysis, api_version in responses

API_VERSION = "1.1.0"


class Settings:
    """
    Application settings loaded from environment variables.
    
    Attributes:
        gemini_api_key: Google Gemini API key for AI analysis
        gemini_enabled: Explicit flag to enable/disable Gemini (default: false)
        environment: Current environment (development, production)
        google_client_id: OAuth client ID for Google login
        google_client_secret: OAuth client secret for Google login
    """
    
    def __init__(self):
        # Environment
        self.environment: str = os.getenv("ENVIRONMENT", "development")
        
        # Gemini settings
        self.gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
        self._gemini_enabled: bool = os.getenv("ENABLE_GEMINI", "false").lower() == "true"
        
        # OAuth settings (Phase 2)
        self.google_client_id: Optional[str] = os.getenv("GOOGLE_CLIENT_ID")
        self.google_client_secret: Optional[str] = os.getenv("GOOGLE_CLIENT_SECRET")
        self.oauth_redirect_uri: str = os.getenv(
            "OAUTH_REDIRECT_URI",
            "http://127.0.0.1:8000/auth/google/callback"
        )
    
    @property
    def is_gemini_enabled(self) -> bool:
        """Check if Gemini API is configured AND explicitly enabled."""
        return bool(self.gemini_api_key) and self._gemini_enabled
    
    @property
    def is_oauth_configured(self) -> bool:
        """Check if Google OAuth is configured."""
        return bool(self.google_client_id and self.google_client_secret)
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses lru_cache to avoid re-reading environment variables on every call.
    """
    return Settings()


# Global settings instance for easy import
settings = get_settings()
