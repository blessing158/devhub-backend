import os
from datetime import datetime, timedelta, timezone

import jwt
import psycopg
from psycopg.rows import dict_row

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, Field
from pwdlib import PasswordHash


app = FastAPI(
    title="DEVHUB API",
    description="Backend API for DEVHUB",
    version="2.0.0"
)


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not configured")


JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 168


# --------------------------------------------------
# SECURITY
# --------------------------------------------------

password_hash = PasswordHash.recommended()
security = HTTPBearer()


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def init_database():

    with get_db() as conn:

        with conn.cursor() as cur:

            # USERS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(30) UNIQUE NOT NULL,
                    phone VARCHAR(30) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    profile_photo TEXT,
                    status VARCHAR(100) DEFAULT 'Hey, I am using DEVHUB',
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # CONVERSATIONS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id BIGSERIAL PRIMARY KEY,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # CONVERSATION MEMBERS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS conversation_members (
                    conversation_id BIGINT NOT NULL
                        REFERENCES conversations(id)
                        ON DELETE CASCADE,

                    user_id BIGINT NOT NULL
                        REFERENCES users(id)
                        ON DELETE CASCADE,

                    PRIMARY KEY (conversation_id, user_id)
                )
            """)

            # MESSAGES
            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id BIGSERIAL PRIMARY KEY,

                    conversation_id BIGINT NOT NULL
                        REFERENCES conversations(id)
                        ON DELETE CASCADE,

                    sender_id BIGINT NOT NULL
                        REFERENCES users(id)
                        ON DELETE CASCADE,

                    message TEXT NOT NULL,

                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

        conn.commit()


# --------------------------------------------------
# STARTUP
# --------------------------------------------------

@app.on_event("startup")
def startup():

    init_database()


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class RegisterRequest(BaseModel):

    username: str = Field(
        min_length=3,
        max_length=30
    )

    phone: str = Field(
        min_length=5,
        max_length=30
    )

    password: str = Field(
        min_length=6,
        max_length=128
    )


class LoginRequest(BaseModel):

    phone: str

    password: str


class MessageRequest(BaseModel):

    message: str = Field(
        min_length=1,
        max_length=5000
    )


# --------------------------------------------------
# JWT
# --------------------------------------------------

def create_token(user_id: int):

    expires = datetime.now(timezone.utc) + timedelta(
        hours=TOKEN_EXPIRE_HOURS
    )

    payload = {
        "sub": str(user_id),
        "exp": expires
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


# --------------------------------------------------
# AUTHENTICATED USER
# --------------------------------------------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = int(payload["sub"])

    except Exception:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    with get_db() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    id,
                    username,
                    phone,
                    profile_photo,
                    status,
                    created_at
                FROM users
                WHERE id = %s
                """,
                (user_id,)
            )

            user = cur.fetchone()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.get("/")
def home():

    return {
        "status": "online",
        "app": "DEVHUB",
        "version": "2.0.0",
        "message": "DEVHUB backend is running"
    }


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.post("/auth/register")
def register(data: RegisterRequest):

    username = data.username.strip().lower()
    phone = data.phone.strip()

    if not username:

        raise HTTPException(
            status_code=400,
            detail="Username is required"
        )

    if not phone:

        raise HTTPException(
            status_code=400,
            detail="Phone number is required"
        )

    with get_db() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT id
                FROM users
                WHERE username = %s
                   OR phone = %s
                """,
                (
                    username,
                    phone
                )
            )

            existing = cur.fetchone()

            if existing:

                raise HTTPException(
                    status_code=409,
                    detail="Username or phone number already exists"
                )

            hashed_password = password_hash.hash(
                data.password
            )

            cur.execute(
                """
                INSERT INTO users
                    (
                        username,
                        phone,
                        password_hash
                    )
                VALUES
                    (
                        %s,
                        %s,
                        %s
                    )
                RETURNING
                    id,
                    username,
                    phone,
                    profile_photo,
                    status,
                    created_at
                """,
                (
                    username,
                    phone,
                    hashed_password
                )
            )

            user = cur.fetchone()

        conn.commit()

    token = create_token(
        user["id"]
    )

    return {
        "success": True,
        "message": "Account created",
        "token": token,
        "user": user
    }


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.post("/auth/login")
def login(data: LoginRequest):

    phone = data.phone.strip()

    with get_db() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT *
                FROM users
                WHERE phone = %s
                """,
                (phone,)
            )

            user = cur.fetchone()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid phone number or password"
        )

    if not password_hash.verify(
        data.password,
        user["password_hash"]
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid phone number or password"
        )

    token = create_token(
        user["id"]
    )

    return {
        "success": True,
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "phone": user["phone"],
            "profile_photo": user["profile_photo"],
            "status": user["status"],
            "created_at": user["created_at"]
        }
    }


# --------------------------------------------------
# CURRENT USER
# --------------------------------------------------

@app.get("/users/me")
def get_me(
    user=Depends(get_current_user)
):

    return {
        "success": True,
        "user": user
    }


# --------------------------------------------------
# SEARCH USERS
# --------------------------------------------------

@app.get("/users/search")
def search_users(
    q: str,
    user=Depends(get_current_user)
):

    query = q.strip().lower()

    if len(query) < 2:

        return {
            "users": []
        }

    with get_db() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    id,
                    username,
                    profile_photo,
                    status
                FROM users
                WHERE username ILIKE %s
                  AND id != %s
                ORDER BY username
                LIMIT 30
                """,
                (
                    f"%{query}%",
                    user["id"]
                )
            )

            users = cur.fetchall()

    return {
        "users": users
    }


# --------------------------------------------------
# CREATE CONVERSATION
# --------------------------------------------------

@app.post("/conversations/{other_user_id}")
def create_conversation(
    other_user_id: int,
    user=Depends(get_current_user)
):

    current_user_id = user["id"]

    if current_user_id == other_user_id:

        raise HTTPException(
            status_code=400,
            detail="You cannot message yourself"
        )

    with get_db() as conn:

        with conn.cursor() as cur:

            # Check other user
            cur.execute(
                """
                SELECT id
                FROM users
                WHERE id = %s
                """,
                (other_user_id,)
            )

            other_user = cur.fetchone()

            if not other_user:

                raise HTTPException(
                    status_code=404,
                    detail="User not found"
                )

            # Check existing conversation
            cur.execute(
                """
                SELECT c.id
                FROM conversations c

                JOIN conversation_members cm1
                    ON c.id = cm1.conversation_id

                JOIN conversation_members cm2
                    ON c.id = cm2.conversation_id

                WHERE cm1.user_id = %s
                  AND cm2.user_id = %s

                GROUP BY c.id
                """,
                (
                    current_user_id,
                    other_user_id
                )
            )

            existing = cur.fetchone()

            if existing:

                return {
                    "success": True,
                    "conversation_id": existing["id"]
                }

            # Create conversation
            cur.execute(
                """
                INSERT INTO conversations
                DEFAULT VALUES
                RETURNING id
                """
            )

            conversation = cur.fetchone()

            conversation_id = conversation["id"]

            # Add members
            cur.execute(
                """
                INSERT INTO conversation_members
                    (
                        conversation_id,
                        user_id
                    )
                VALUES
                    (%s, %s),
                    (%s, %s)
                """,
                (
                    conversation_id,
                    current_user_id,
                    conversation_id,
                    other_user_id
                )
            )

        conn.commit()

    return {
        "success": True,
        "conversation_id": conversation_id
    }


# --------------------------------------------------
# SEND MESSAGE
# --------------------------------------------------

@app.post("/conversations/{conversation_id}/messages")
def send_message(
    conversation_id: int,
    data: MessageRequest,
    user=Depends(get_current_user)
):

    message_text = data.message.strip()

    if not message_text:

        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty"
        )

    with get_db() as conn:

        with conn.cursor() as cur:

            # Verify membership
            cur.execute(
                """
                SELECT 1
                FROM conversation_members
                WHERE conversation_id = %s
                  AND user_id = %s
                """,
                (
                    conversation_id,
                    user["id"]
                )
            )

            member = cur.fetchone()

            if not member:

                raise HTTPException(
                    status_code=403,
                    detail="You are not a member of this conversation"
                )

            # Insert message
            cur.execute(
                """
                INSERT INTO messages
                    (
                        conversation_id,
                        sender_id,
                        message
                    )
                VALUES
                    (
                        %s,
                        %s,
                        %s
                    )
                RETURNING
                    id,
                    conversation_id,
                    sender_id,
                    message,
                    created_at
                """,
                (
                    conversation_id,
                    user["id"],
                    message_text
                )
            )

            message = cur.fetchone()

        conn.commit()

    return {
        "success": True,
        "message": message
    }


# --------------------------------------------------
# GET MESSAGES
# --------------------------------------------------

@app.get("/conversations/{conversation_id}/messages")
def get_messages(
    conversation_id: int,
    user=Depends(get_current_user)
):

    with get_db() as conn:

        with conn.cursor() as cur:

            # Verify membership
            cur.execute(
                """
                SELECT 1
                FROM conversation_members
                WHERE conversation_id = %s
                  AND user_id = %s
                """,
                (
                    conversation_id,
                    user["id"]
                )
            )

            member = cur.fetchone()

            if not member:

                raise HTTPException(
                    status_code=403,
                    detail="You are not a member of this conversation"
                )

            # Get messages
            cur.execute(
                """
                SELECT
                    m.id,
                    m.conversation_id,
                    m.sender_id,
                    u.username AS sender_username,
                    m.message,
                    m.created_at
                FROM messages m

                JOIN users u
                    ON u.id = m.sender_id

                WHERE m.conversation_id = %s

                ORDER BY m.created_at ASC
                """,
                (conversation_id,)
            )

            messages = cur.fetchall()

    return {
        "messages": messages
}
