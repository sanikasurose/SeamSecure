# SeamSecure — Backend

This folder contains the **FastAPI backend** for the SeamSecure project.

## Tech Stack
- Python 3.12
- FastAPI
- Uvicorn
- Pydantic

## Setup

### 1. Activate Virtual Environment
From the `backend/` directory:
```bash
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Server
```bash
uvicorn app.main:app --reload
```
- API runs at: http://127.0.0.1:8000
- Docs available at: http://127.0.0.1:8000/docs

## Notes
- venv/ is gitignored
- This README covers only what is currently implemented