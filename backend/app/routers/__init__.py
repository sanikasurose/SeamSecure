# Name: __init__.py
# Description: Export all routers for convenient importing
# Date: 2026-01-31

from app.routers.thread_router import router as thread_router
from app.routers.auth_router import router as auth_router
from app.routers.gmail_router import router as gmail_router

__all__ = ["thread_router", "auth_router", "gmail_router"]
