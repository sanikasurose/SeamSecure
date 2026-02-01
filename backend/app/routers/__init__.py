# Name: __init__.py
# Description: Export all routers for convenient importing
# Date: 2026-01-31

from app.routers.thread_router import router as thread_router

__all__ = ["thread_router"]
