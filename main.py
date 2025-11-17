import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Utility helpers
# ---------------------------

def oid_str(oid: ObjectId | str) -> str:
    return str(oid)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, h


# ---------------------------
# Request/response models
# ---------------------------

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    token: str
    user: dict


class SyllabusCreateRequest(BaseModel):
    title: str
    course_code: Optional[str] = None
    description: Optional[str] = None
    objectives: List[str] = []
    level: Optional[str] = None
    subject: Optional[str] = None
    duration_weeks: Optional[int] = None
    weeks: List[dict] = []


class SyllabusResponse(BaseModel):
    id: str
    title: str
    course_code: Optional[str] = None
    description: Optional[str] = None
    objectives: List[str] = []
    level: Optional[str] = None
    subject: Optional[str] = None
    duration_weeks: Optional[int] = None
    weeks: List[dict] = []
    created_at: Optional[str] = None


# ---------------------------
# Auth dependency (simple session token)
# ---------------------------

def get_current_user(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = authorization.replace("Bearer ", "").strip()

    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")
    user = db["user"].find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["id"] = oid_str(user.pop("_id"))
    return user


# ---------------------------
# Health & schema endpoints
# ---------------------------

@app.get("/")
def read_root():
    return {"message": "SaaS Syllabus Builder API"}


@app.get("/schema")
def get_schema():
    # Expose schemas to database viewer (if used)
    from schemas import User, Session, Syllabus
    return {
        "user": User.model_json_schema(),
        "session": Session.model_json_schema(),
        "syllabus": Syllabus.model_json_schema(),
    }


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, "name") else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# ---------------------------
# Auth routes
# ---------------------------

@app.post("/auth/register", response_model=AuthResponse)
def register(req: RegisterRequest):
    # Check existing
    existing = db["user"].find_one({"email": req.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    salt, pw_hash = hash_password(req.password)
    user_doc = {
        "name": req.name,
        "email": req.email.lower(),
        "password_salt": salt,
        "password_hash": pw_hash,
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    result = db["user"].insert_one(user_doc)
    user_id = str(result.inserted_id)

    token = secrets.token_urlsafe(32)
    db["session"].insert_one(
        {
            "user_id": user_id,
            "token": token,
            "user_agent": None,
            "created_at": now_iso(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        }
    )

    user_out = {"id": user_id, "name": req.name, "email": req.email.lower()}
    return {"token": token, "user": user_out}


@app.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email.lower()})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    salt = user.get("password_salt")
    _, h = hash_password(req.password, salt)
    if h != user.get("password_hash"):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    db["session"].insert_one(
        {
            "user_id": str(user["_id"]),
            "token": token,
            "user_agent": None,
            "created_at": now_iso(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        }
    )

    user_out = {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}
    return {"token": token, "user": user_out}


@app.post("/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    if not authorization:
        return {"ok": True}
    token = authorization.replace("Bearer ", "").strip()
    db["session"].delete_many({"token": token})
    return {"ok": True}


# ---------------------------
# Syllabus routes
# ---------------------------

@app.post("/syllabi", response_model=SyllabusResponse)
def create_syllabus(payload: SyllabusCreateRequest, user=Depends(get_current_user)):
    doc = {
        "owner_id": user["id"],
        "title": payload.title,
        "course_code": payload.course_code,
        "description": payload.description,
        "objectives": payload.objectives or [],
        "level": payload.level,
        "subject": payload.subject,
        "duration_weeks": payload.duration_weeks,
        "weeks": payload.weeks or [],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    result = db["syllabus"].insert_one(doc)
    doc_out = doc | {"id": str(result.inserted_id)}
    return doc_out


@app.get("/syllabi", response_model=List[SyllabusResponse])
def list_syllabi(user=Depends(get_current_user)):
    items = list(db["syllabus"].find({"owner_id": user["id"]}).sort("created_at", -1))
    out: List[SyllabusResponse] = []
    for it in items:
        it["id"] = str(it.pop("_id"))
        out.append(SyllabusResponse(**it))
    return out


@app.get("/syllabi/{syllabus_id}", response_model=SyllabusResponse)
def get_syllabus(syllabus_id: str, user=Depends(get_current_user)):
    doc = db["syllabus"].find_one({"_id": ObjectId(syllabus_id), "owner_id": user["id"]})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc.pop("_id"))
    return SyllabusResponse(**doc)


# ---------------------------
# AI Chatbot with predetermined prompt via form inputs
# ---------------------------

class ChatRequest(BaseModel):
    course_title: str
    subject: Optional[str] = None
    level: Optional[str] = None
    goals: List[str] = []
    constraints: Optional[str] = None


class ChatResponse(BaseModel):
    prompt: str
    outline: List[str]


@app.post("/ai/chat", response_model=ChatResponse)
def ai_chat(req: ChatRequest, user=Depends(get_current_user)):
    # Predetermined system prompt using form inputs
    base_prompt = (
        "You are an expert course designer. Given the course title, subject, level, "
        "goals, and any constraints, produce a practical syllabus outline with 8-12 "
        "weekly topics. Keep topics concise and actionable."
    )

    # Build the composed prompt text
    parts = [
        f"Course Title: {req.course_title}",
        f"Subject: {req.subject or 'General'}",
        f"Level: {req.level or 'Mixed'}",
        f"Goals: {', '.join(req.goals) if req.goals else 'N/A'}",
        f"Constraints: {req.constraints or 'None'}",
    ]
    composed = base_prompt + "\n\n" + "\n".join(parts)

    # For this environment, we'll generate a mock outline deterministically
    # based on inputs instead of calling external LLMs.
    seed = (req.course_title + (req.subject or '') + (req.level or '')).strip()
    count = max(8, min(12, 4 + (len(seed) % 9)))
    outline = [f"Week {i+1}: Topic derived from '{req.course_title}' - Part {i+1}" for i in range(count)]

    return ChatResponse(prompt=composed, outline=outline)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
