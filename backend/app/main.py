from fastapi import FastAPI

app = FastAPI(title="SeamSecure API")

@app.get("/")
def root():
    return {"message": "SeamSecure backend is running"}

@app.get("/health")
def health_check():
    return {"status": "ok"}
