from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import thread_router

app = FastAPI(
    title="SeamSecure API",
    description="Email thread security analysis API",
    version="0.1.0",
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

# ---------- Root Endpoints ----------


@app.get("/")
def root():
    return {"message": "SeamSecure backend is running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}
