# SeamSecure

**AI-powered email security analysis to protect you from phishing threats.**

SeamSecure is a full-stack web application that analyzes email threads for potential security risks, combining rule-based heuristics with Google Gemini AI to detect phishing attempts, suspicious sender patterns, and other email-based threats.

---

## Features

- **Dual Analysis Modes**
  - **Paste Email**: Analyze any email thread by pasting its content
  - **Gmail Integration**: Connect your Gmail account and analyze emails directly from your inbox

- **Hybrid Threat Detection**
  - **Rule-Based Analysis**: Detects urgency language, sensitive data requests, suspicious links, and sender anomalies
  - **AI-Powered Analysis**: Google Gemini integration for intent drift detection, style anomalies, sentiment shifts, and contextual risk assessment

- **Risk Assessment**
  - Risk scoring (0-100%) with severity weighting
  - Three-tier risk levels: Safe, Suspicious, Dangerous
  - Detailed indicators with human-readable explanations

- **Google OAuth Integration**
  - Secure Gmail authentication
  - Read-only access to email content
  - Session management with secure token handling

---

## Tech Stack

### Backend
| Technology | Purpose |
|------------|---------|
| Python 3.12 | Runtime |
| FastAPI | Web framework |
| Uvicorn | ASGI server |
| Pydantic | Data validation |
| Google GenAI | Gemini AI integration |
| python-dotenv | Environment management |

### Frontend
| Technology | Purpose |
|------------|---------|
| React 18 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool & dev server |
| Tailwind CSS 4 | Styling |

---

## Project Structure

```
SeamSecure/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── config.py        # Settings & environment variables
│   │   │   └── security.py      # Security utilities
│   │   ├── models/
│   │   │   └── thread.py        # Pydantic models
│   │   ├── routers/
│   │   │   ├── auth_router.py   # Google OAuth endpoints
│   │   │   ├── gmail_router.py  # Gmail API endpoints
│   │   │   └── thread_router.py # Thread analysis endpoints
│   │   ├── services/
│   │   │   ├── analysis_service.py  # Core analysis logic
│   │   │   ├── gemini_service.py    # Gemini AI integration
│   │   │   ├── gmail_service.py     # Gmail API service
│   │   │   └── scoring.py           # Risk scoring algorithms
│   │   └── main.py              # FastAPI application entry
│   ├── requirements.txt
│   └── API_CONTRACT.md          # Detailed API documentation
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── gmail.ts         # Gmail API client
│   │   │   └── seamsecure.ts    # Analysis API client
│   │   ├── components/
│   │   │   ├── GmailThreadList.tsx  # Gmail thread list
│   │   │   ├── IndicatorList.tsx    # Risk indicators display
│   │   │   └── RiskBadge.tsx        # Risk level badge
│   │   ├── types/
│   │   │   └── api.ts           # TypeScript interfaces
│   │   ├── utils/
│   │   │   └── emailParser.ts   # Email parsing utilities
│   │   ├── App.tsx              # Main application
│   │   ├── main.tsx             # Entry point
│   │   └── index.css            # Global styles
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
├── .env                         # Environment variables (gitignored)
└── README.md
```

---

## Prerequisites

- **Python** 3.12+
- **Node.js** 18+ and npm
- **Google Cloud Project** (for Gmail OAuth and Gemini API)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/SeamSecure.git
cd SeamSecure
```

### 2. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install
```

### 4. Environment Configuration

Create a `.env` file in the project root (or `backend/` directory):

```env
# Environment
ENVIRONMENT=development

# Gemini AI (optional - enables AI-powered analysis)
GEMINI_API_KEY=your_gemini_api_key
ENABLE_GEMINI=true

# Google OAuth (optional - enables Gmail integration)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
OAUTH_REDIRECT_URI=http://127.0.0.1:8000/auth/google/callback
```

#### Getting API Keys

**Gemini API Key:**
1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Create an API key
3. Add it to your `.env` file

**Google OAuth Credentials:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable the Gmail API
4. Configure OAuth consent screen
5. Create OAuth 2.0 credentials (Web application)
6. Add authorized redirect URI: `http://127.0.0.1:8000/auth/google/callback`
7. Add client ID and secret to your `.env` file

---

## Running the Application

### Start Backend Server

```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload
```

The API will be available at: `http://127.0.0.1:8000`

### Start Frontend Dev Server

```bash
cd frontend
npm run dev
```

The frontend will be available at: `http://localhost:5173`

---

## API Documentation

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze-thread` | Analyze an email thread for security risks |
| `GET` | `/auth/google` | Initiate Google OAuth flow |
| `GET` | `/auth/google/callback` | OAuth callback handler |
| `GET` | `/gmail/threads` | Fetch Gmail threads |
| `GET` | `/gmail/analyze/{thread_id}` | Analyze a Gmail thread |
| `GET` | `/health` | Health check |
| `GET` | `/status` | Detailed status with feature availability |

### Interactive Documentation

Once the backend is running:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

For detailed API specifications, see [backend/API_CONTRACT.md](backend/API_CONTRACT.md).

---

## Risk Analysis Details

### Indicator Types

**Rule-Based (always available):**
| Indicator | Severity | Description |
|-----------|----------|-------------|
| `urgency_language` | Medium | Urgent phrases like "act now", "immediately" |
| `sensitive_request` | High | Requests for passwords, SSN, financial info |
| `external_links` | Medium/High | Suspicious URLs, IP addresses, URL shorteners |
| `sender_anomaly` | Low-High | Domain impersonation, typosquatting |

**AI-Powered (when Gemini is enabled):**
| Indicator | Severity | Description |
|-----------|----------|-------------|
| `intent_drift` | Medium/High | Thread intent changed suspiciously |
| `ai_urgency_detected` | Medium | AI detected urgency patterns |
| `style_anomaly` | Medium | Writing style inconsistency |
| `sentiment_shift` | Medium | Suspicious tone changes |
| `ai_high_risk` | High | AI classified as high-risk |

### Risk Levels

| Score Range | Level | UI Color |
|-------------|-------|----------|
| < 30% | Safe | Green |
| 30% - 70% | Suspicious | Yellow/Orange |
| ≥ 70% | Dangerous | Red |

---

## Development

### Running Tests

```bash
cd backend
pytest
```

### Building for Production

**Frontend:**
```bash
cd frontend
npm run build
```

**Backend:**
Configure production environment variables and run with:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Security Notes

- Email content is analyzed in real-time and not stored on the server
- Gmail OAuth uses read-only scopes
- Sessions are managed securely with proper token handling
- All API communications use CORS protection
- Sensitive credentials are stored in environment variables (never committed)

---

## License

This project is for educational and demonstration purposes.

---

## Acknowledgments

- [Google Gemini AI](https://ai.google.dev/) for AI-powered threat analysis
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- [React](https://react.dev/) and [Vite](https://vitejs.dev/) for the modern frontend tooling
- [Tailwind CSS](https://tailwindcss.com/) for utility-first styling
