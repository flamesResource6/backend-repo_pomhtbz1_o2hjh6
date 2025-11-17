"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Syllabus -> "syllabus" collection
- Session -> "session" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, List

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    password_salt: str = Field(..., description="Salt used for hashing")
    password_hash: str = Field(..., description="Password hash")

class Session(BaseModel):
    """User sessions (simple token-based sessions)"""
    user_id: str = Field(..., description="User id (stringified ObjectId)")
    token: str = Field(..., description="Session token")
    user_agent: Optional[str] = Field(None, description="Client user agent")
    expires_at: Optional[str] = Field(None, description="ISO timestamp of expiration")

class WeekPlan(BaseModel):
    week: int
    topics: List[str] = []
    readings: List[str] = []
    assignments: List[str] = []

class Syllabus(BaseModel):
    """
    Syllabuses collection schema
    Collection name: "syllabus"
    """
    owner_id: str = Field(..., description="Owner user id")
    title: str
    course_code: Optional[str] = None
    description: Optional[str] = None
    objectives: List[str] = []
    weeks: List[WeekPlan] = []
    level: Optional[str] = None
    subject: Optional[str] = None
    duration_weeks: Optional[int] = None
