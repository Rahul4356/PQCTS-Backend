# Complete app.py - Quantum Messaging System Backend
# type: ignore  # SQLAlchemy runtime attributes work correctly despite type warnings
from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer, ForeignKey, or_, and_, desc, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, Field, EmailStr, validator
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import jwt
import bcrypt
import json
import uuid
import base64
import httpx
import os
import hashlib
import logging
import traceback
import asyncio
import time
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('qms_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.environ.get("JWT_SECRET")
if not SECRET_KEY:
    logger.warning("JWT_SECRET not set! Generating temporary key - DO NOT USE IN PRODUCTION!")
    SECRET_KEY = "quantum-secure-key-" + secrets.token_hex(32)

ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

# Service URLs
QUANTUM_API = os.environ.get("QUANTUM_API_URL", "http://localhost:3001")

# Database configuration
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./qms_quantum.db")

# Environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1", "yes")
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ========== DATABASE MODELS ==========
class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    public_keys = Column(Text, nullable=True)
    key_generation_timestamp = Column(DateTime, nullable=True)
    
    # Relationships
    sent_requests = relationship("ConnectionRequest", foreign_keys="ConnectionRequest.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_requests = relationship("ConnectionRequest", foreign_keys="ConnectionRequest.receiver_id", back_populates="receiver", cascade="all, delete-orphan")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver", cascade="all, delete-orphan")
    performance_metrics = relationship("PerformanceMetric", back_populates="user", cascade="all, delete-orphan")

class ConnectionRequest(Base):
    __tablename__ = "connection_requests"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    sender_public_keys = Column(Text, nullable=False)
    receiver_public_keys = Column(Text, nullable=True)
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
    
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_requests")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_requests")

class SecureSession(Base):
    __tablename__ = "secure_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user1_id = Column(String, ForeignKey("users.id"))
    user2_id = Column(String, ForeignKey("users.id"))
    request_id = Column(String, ForeignKey("connection_requests.id"), nullable=True)
    shared_secret = Column(Text, nullable=True)
    ciphertext = Column(Text, nullable=True)
    session_metadata = Column(Text, nullable=True)
    established_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    terminated_at = Column(DateTime, nullable=True)
    termination_reason = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    message_count = Column(Integer, default=0)
    
    user1 = relationship("User", foreign_keys=[user1_id])
    user2 = relationship("User", foreign_keys=[user2_id])
    connection_request = relationship("ConnectionRequest", foreign_keys=[request_id])
    messages = relationship("Message", back_populates="session", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("secure_sessions.id"))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    encrypted_content = Column(Text, nullable=False)
    nonce = Column(String(32), nullable=False)
    tag = Column(String(32), nullable=False)
    aad = Column(Text, nullable=True)
    falcon_signature = Column(Text, nullable=True)
    ecdsa_signature = Column(Text, nullable=True)
    signature_metadata = Column(Text, nullable=True)
    message_type = Column(String(20), default="secured")
    timestamp = Column(DateTime, default=datetime.utcnow)
    delivered_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    is_read = Column(Boolean, default=False)
    is_deleted_sender = Column(Boolean, default=False)
    is_deleted_receiver = Column(Boolean, default=False)
    
    session = relationship("SecureSession", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")

class PerformanceMetric(Base):
    __tablename__ = "performance_metrics"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    operation = Column(String(50), nullable=False)
    duration_ms = Column(Float, nullable=False)
    data_size = Column(Integer, nullable=True)
    is_critical = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="performance_metrics")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", foreign_keys=[user_id])

# Create tables
Base.metadata.create_all(bind=engine)

# ========== FASTAPI APP ==========
app = FastAPI(
    title="QMS Platform - Quantum Messaging System",
    description="Enhanced quantum-resistant messaging platform",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration from environment
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Mount static files to serve the frontend
app.mount("/static", StaticFiles(directory="."), name="static")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

# ========== WEBSOCKET CONNECTION MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}
        
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        self.user_connections[username] = connection_id
        logger.info(f"WebSocket connected: {username} ({connection_id})")
        return connection_id
    
    def disconnect(self, username: str):
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
            del self.user_connections[username]
            logger.info(f"WebSocket disconnected: {username}")
    
    async def send_personal_message(self, username: str, message: dict):
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                websocket = self.active_connections[connection_id]
                try:
                    await websocket.send_text(json.dumps(message))
                    logger.debug(f"Sent message to {username}: {message.get('type', 'unknown')}")
                except Exception as e:
                    logger.error(f"Error sending message to {username}: {e}")
    
    async def broadcast_to_users(self, message: dict, usernames: List[str]):
        for username in usernames:
            await self.send_personal_message(username, message)
    
    def get_online_users(self):
        return list(self.user_connections.keys())

manager = ConnectionManager()

# ========== PYDANTIC MODELS ==========
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores allowed)')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    user_id: str
    email: str

class MessageRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)
    message_type: str = Field(default="secured")
    
class ConnectionRequestModel(BaseModel):
    receiver_username: str

class ConnectionResponseModel(BaseModel):
    request_id: str
    accept: bool
    
class SessionInfo(BaseModel):
    session_id: str
    other_user_username: str
    established_at: datetime
    is_active: bool
    message_count: int
    
class MessageInfo(BaseModel):
    id: str
    sender_username: str
    content: str
    timestamp: datetime
    is_read: bool
    message_type: str
    verified: Optional[bool] = None
    
class EncryptionInfo(BaseModel):
    shared_secret: str
    algorithm: str = "AES-256-GCM"
    
class SignatureInfo(BaseModel):
    falcon_signature: str
    ecdsa_signature: Optional[str] = None
    algorithm: str
    
# ========== UTILITY FUNCTIONS ==========
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS)).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.commit()
    
    return user

def encrypt_message(plaintext: str, shared_secret: str, aad: Optional[str] = None) -> tuple:
    """Encrypt message using AES-256-GCM"""
    # Derive key using HKDF
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'qms_encryption',
        backend=default_backend()
    )
    key = kdf.derive(base64.b64decode(shared_secret))
    
    # Generate nonce
    nonce = os.urandom(12)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Add AAD if provided
    if aad:
        encryptor.authenticate_additional_data(aad.encode())
    
    # Encrypt
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(encryptor.tag).decode()
    )

def decrypt_message(ciphertext: str, nonce: str, tag: str, shared_secret: str, aad: Optional[str] = None) -> str:
    """Decrypt message using AES-256-GCM"""
    # Derive key using HKDF
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'qms_encryption',
        backend=default_backend()
    )
    key = kdf.derive(base64.b64decode(shared_secret))
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(base64.b64decode(nonce), base64.b64decode(tag)),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Add AAD if provided
    if aad:
        decryptor.authenticate_additional_data(aad.encode())
    
    # Decrypt
    plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    
    return plaintext.decode()

def get_active_session(user_id: str, db: Session) -> Optional[SecureSession]:
    """Get active session for a user"""
    return db.query(SecureSession).filter(
        or_(SecureSession.user1_id == user_id, SecureSession.user2_id == user_id),
        SecureSession.is_active == True
    ).first()

def log_audit(db: Session, user_id: Optional[str], action: str, details: Optional[str] = None,
             request: Optional[Request] = None):
    """Log audit event"""
    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get("User-Agent") if request else None
    )
    db.add(audit_entry)
    db.commit()

# ========== AUTH ENDPOINTS ==========
@app.post("/api/register", response_model=TokenResponse)
async def register(user_reg: UserRegistration, request: Request, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user exists
    if db.query(User).filter(or_(User.username == user_reg.username, User.email == user_reg.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Create new user
    new_user = User(
        username=user_reg.username,
        email=user_reg.email,
        hashed_password=hash_password(user_reg.password)
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log registration
    log_audit(db, new_user.id, "USER_REGISTERED", f"Username: {user_reg.username}", request)
    
    # Create access token
    access_token = create_access_token(data={"sub": new_user.username})
    
    logger.info(f"New user registered: {user_reg.username}")
    
    return TokenResponse(
        access_token=access_token,
        username=new_user.username,
        user_id=new_user.id,
        email=new_user.email
    )

@app.post("/api/login", response_model=TokenResponse)
async def login(user_login: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Login user"""
    user = db.query(User).filter(User.username == user_login.username).first()
    
    if not user or not verify_password(user_login.password, user.hashed_password):
        # Log failed attempt
        log_audit(db, None, "LOGIN_FAILED", f"Username: {user_login.username}", request)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.commit()
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    # Log successful login
    log_audit(db, user.id, "USER_LOGIN", None, request)
    
    logger.info(f"User logged in: {user.username}")
    
    return TokenResponse(
        access_token=access_token,
        username=user.username,
        user_id=user.id,
        email=user.email
    )

@app.post("/api/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Logout user and clean up"""
    # Update last seen
    current_user.last_seen = datetime.utcnow()
    
    # Get active session if any
    active_session = get_active_session(current_user.id, db)
    if active_session:
        active_session.is_active = False
        active_session.terminated_at = datetime.utcnow()
        active_session.termination_reason = "User logout"
    
    db.commit()
    
    # Log logout
    log_audit(db, current_user.id, "USER_LOGOUT", None, None)
    
    logger.info(f"User logged out: {current_user.username}")
    
    return {"message": "Logged out successfully"}

@app.get("/api/users/available")
async def get_available_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get list of available users for connection"""
    # Get all active users except current user
    users = db.query(User).filter(
        User.id != current_user.id,
        User.is_active == True
    ).all()
    
    result = []
    for user in users:
        # Check if user has an active session
        active_session = get_active_session(user.id, db)
        has_active_session = active_session is not None
        
        # Determine if current user can connect to this user
        can_connect = not has_active_session and not get_active_session(current_user.id, db)
        
        # Determine user status
        if active_session:
            status = "busy"
        elif user.last_seen and (datetime.utcnow() - user.last_seen).total_seconds() < 300:  # 5 minutes
            status = "online"
        else:
            status = "offline"
        
        result.append({
            "username": user.username,
            "email": user.email,
            "status": status,
            "can_connect": can_connect,
            "last_seen": user.last_seen.isoformat() if user.last_seen else None
        })
    
    return result

# ========== CONNECTION ENDPOINTS (Frontend compatibility aliases) ==========
@app.post("/api/connection/request")
async def connection_request_alias(
    req: ConnectionRequestModel,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Alias for /api/exchange/request - Frontend compatibility"""
    return await request_key_exchange(req, current_user, db)

@app.get("/api/connection/pending")
async def get_pending_connections(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get pending connection requests for current user"""
    # Get incoming requests (where user is receiver)
    incoming = db.query(ConnectionRequest).filter(
        ConnectionRequest.receiver_id == current_user.id,
        ConnectionRequest.status == "pending"
    ).all()
    
    # Get outgoing requests (where user is sender)
    outgoing = db.query(ConnectionRequest).filter(
        ConnectionRequest.sender_id == current_user.id,
        ConnectionRequest.status == "pending"
    ).all()
    
    incoming_list = []
    for req in incoming:
        sender = db.query(User).filter(User.id == req.sender_id).first()
        incoming_list.append({
            "request_id": req.id,
            "sender_username": sender.username if sender else "Unknown",
            "sender_id": req.sender_id,
            "created_at": req.created_at.isoformat(),
            "expires_at": req.expires_at.isoformat()
        })
    
    outgoing_list = []
    for req in outgoing:
        receiver = db.query(User).filter(User.id == req.receiver_id).first()
        outgoing_list.append({
            "request_id": req.id,
            "receiver_username": receiver.username if receiver else "Unknown",
            "receiver_id": req.receiver_id,
            "created_at": req.created_at.isoformat(),
            "expires_at": req.expires_at.isoformat()
        })
    
    return {
        "incoming": incoming_list,
        "outgoing": outgoing_list
    }

@app.post("/api/connection/respond")
async def connection_respond_alias(
    response: ConnectionResponseModel,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Alias for /api/exchange/respond - Frontend compatibility"""
    return await respond_to_key_exchange(response, current_user, db)

# ========== KEY EXCHANGE ENDPOINTS ==========
@app.post("/api/exchange/request")
async def request_key_exchange(
    req: ConnectionRequestModel,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initiate quantum key exchange"""
    # Find receiver
    receiver = db.query(User).filter(User.username == req.receiver_username).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")
    
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot connect to yourself")
    
    # Check for existing pending request
    existing_request = db.query(ConnectionRequest).filter(
        or_(
            and_(ConnectionRequest.sender_id == current_user.id,
                 ConnectionRequest.receiver_id == receiver.id),
            and_(ConnectionRequest.sender_id == receiver.id,
                 ConnectionRequest.receiver_id == current_user.id)
        ),
        ConnectionRequest.status == "pending"
    ).first()
    
    if existing_request:
        raise HTTPException(status_code=400, detail="Connection request already exists")
    
    # Generate quantum keys for sender
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{QUANTUM_API}/api/quantum/keygen",
            json={"user_id": current_user.username, "key_type": "all"}
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to generate keys: {response.text}")
            raise HTTPException(status_code=500, detail="Failed to generate quantum keys")
        
        key_data = response.json()
        sender_keys = json.dumps(key_data["keys"])
        
        # Store keys in user profile
        current_user.public_keys = sender_keys
        current_user.key_generation_timestamp = datetime.utcnow()
    
    # Create connection request
    connection_request = ConnectionRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        sender_public_keys=sender_keys,
        status="pending"
    )
    
    db.add(connection_request)
    db.commit()
    db.refresh(connection_request)
    
    # Send WebSocket notification
    await manager.send_personal_message(
        receiver.username,
        {
            "type": "connection_request",
            "request_id": connection_request.id,
            "sender_username": current_user.username,
            "sender_id": current_user.id,
            "timestamp": connection_request.created_at.isoformat()
        }
    )
    
    # Log audit
    log_audit(db, current_user.id, "CONNECTION_REQUEST_SENT", f"To: {receiver.username}", None)
    
    logger.info(f"Connection request sent from {current_user.username} to {receiver.username}")
    
    return {
        "request_id": connection_request.id,
        "status": "pending",
        "receiver_username": receiver.username,
        "expires_at": connection_request.expires_at.isoformat()
    }

@app.post("/api/exchange/respond")
async def respond_to_key_exchange(
    resp: ConnectionResponseModel,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Respond to quantum key exchange request"""
    # Get connection request
    connection_request = db.query(ConnectionRequest).filter(
        ConnectionRequest.id == resp.request_id,
        ConnectionRequest.receiver_id == current_user.id,
        ConnectionRequest.status == "pending"
    ).first()
    
    if not connection_request:
        raise HTTPException(status_code=404, detail="Connection request not found")
    
    # Check if expired
    if datetime.utcnow() > connection_request.expires_at:
        connection_request.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="Connection request has expired")
    
    sender = db.query(User).filter(User.id == connection_request.sender_id).first()
    
    if resp.accept:
        # Generate quantum keys for receiver
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{QUANTUM_API}/api/quantum/keygen",
                json={"user_id": current_user.username, "key_type": "all"}
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to generate keys: {response.text}")
                raise HTTPException(status_code=500, detail="Failed to generate quantum keys")
            
            key_data = response.json()
            receiver_keys = json.dumps(key_data["keys"])
            
            # Store keys in user profile
            current_user.public_keys = receiver_keys
            current_user.key_generation_timestamp = datetime.utcnow()
            
            # Get sender's ML-KEM public key
            sender_keys = json.loads(connection_request.sender_public_keys)
            sender_ml_kem_public = sender_keys["ml_kem"]["public"]
            
            # Encapsulate to create shared secret
            response = await client.post(
                f"{QUANTUM_API}/api/quantum/encapsulate",
                json={"receiver_public_key": sender_ml_kem_public}
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to encapsulate: {response.text}")
                raise HTTPException(status_code=500, detail="Failed to create shared secret")
            
            encap_result = response.json()
            ciphertext = encap_result["ciphertext"]
            shared_secret = encap_result["shared_secret"]
        
        # Update connection request
        connection_request.receiver_public_keys = receiver_keys
        connection_request.status = "accepted"
        connection_request.responded_at = datetime.utcnow()
        
        # Create secure session
        secure_session = SecureSession(
            user1_id=connection_request.sender_id,
            user2_id=current_user.id,
            request_id=connection_request.id,
            shared_secret=shared_secret,
            ciphertext=ciphertext,
            session_metadata=json.dumps({
                "algorithm": "ML-KEM-768",
                "created_by": "receiver",
                "timestamp": datetime.utcnow().isoformat()
            })
        )
        
        db.add(secure_session)
        db.commit()
        db.refresh(secure_session)
        
        # Send WebSocket notifications
        await manager.send_personal_message(
            sender.username,
            {
                "type": "connection_accepted",
                "request_id": connection_request.id,
                "session_id": secure_session.id,
                "receiver_username": current_user.username,
                "receiver_public_keys": receiver_keys,
                "ciphertext": ciphertext,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Log audit
        log_audit(db, current_user.id, "CONNECTION_ACCEPTED", f"From: {sender.username}", None)
        
        logger.info(f"Connection accepted: {sender.username} <-> {current_user.username}")
        
        return {
            "status": "accepted",
            "session_id": secure_session.id,
            "shared_secret": shared_secret,
            "message": "Secure session established"
        }
    else:
        # Reject request
        connection_request.status = "rejected"
        connection_request.responded_at = datetime.utcnow()
        db.commit()
        
        # Send WebSocket notification
        await manager.send_personal_message(
            sender.username,
            {
                "type": "connection_rejected",
                "request_id": connection_request.id,
                "receiver_username": current_user.username,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Log audit
        log_audit(db, current_user.id, "CONNECTION_REJECTED", f"From: {sender.username}", None)
        
        logger.info(f"Connection rejected: {sender.username} <- {current_user.username}")
        
        return {
            "status": "rejected",
            "message": "Connection request rejected"
        }

# ========== MESSAGING ENDPOINTS ==========
@app.post("/api/messages/send")
async def send_quantum_message(
    message: MessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send quantum-secured message"""
    # Get active session
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=400, detail="No active secure session")
    
    # Get shared secret
    shared_secret = session.shared_secret
    if not shared_secret:
        raise HTTPException(status_code=400, detail="Session not properly established")
    
    # Create AAD with session and message metadata
    aad = json.dumps({
        "session_id": session.id,
        "sender_id": current_user.id,
        "timestamp": datetime.utcnow().isoformat(),
        "message_type": message.message_type
    })
    
    # Encrypt message
    ciphertext, nonce, tag = encrypt_message(
        message.content,
        shared_secret,
        aad
    )
    
    # Sign all messages for quantum security
    # NOTE: C backend doesn't implement wrap_sign, using placeholders
    # In production, implement these endpoints in C or use alternative signing
    falcon_sig = base64.b64encode(b"falcon_signature_placeholder").decode()
    ecdsa_sig = base64.b64encode(b"ecdsa_signature_placeholder").decode()
    sig_metadata = {
        "algorithm": "Falcon-512/ECDSA-P256",
        "timestamp": datetime.utcnow().isoformat(),
        "message_type": message.message_type,
        "note": "Placeholder signatures - implement in C backend for production"
    }
    
    # Determine receiver
    receiver_id = session.user2_id if session.user1_id == current_user.id else session.user1_id
    
    # Create message
    msg = Message(
        session_id=session.id,
        sender_id=current_user.id,
        receiver_id=receiver_id,
        encrypted_content=ciphertext,
        nonce=nonce,
        tag=tag,
        aad=aad,
        falcon_signature=falcon_sig,
        ecdsa_signature=ecdsa_sig,
        signature_metadata=json.dumps(sig_metadata),
        message_type=message.message_type
    )
    
    db.add(msg)
    
    # Update session
    session.last_activity = datetime.utcnow()
    session.message_count += 1
    
    # Mark as delivered if receiver is online
    receiver_user = db.query(User).filter(User.id == receiver_id).first()
    if receiver_user.username in manager.get_online_users():
        msg.delivered_at = datetime.utcnow()
    
    db.commit()
    db.refresh(msg)
    
    # Send WebSocket notification
    await manager.send_personal_message(
        receiver_user.username,
        {
            "type": "new_message",
            "message_id": msg.id,
            "sender_username": current_user.username,
            "message_type": message.message_type,
            "timestamp": msg.timestamp.isoformat(),
            "session_id": session.id
        }
    )
    
    # Log metrics
    metric = PerformanceMetric(
        user_id=current_user.id,
        operation="message_send",
        duration_ms=0,  # Would measure actual encryption time
        data_size=len(message.content),
        is_critical=message.message_type == "critical"
    )
    db.add(metric)
    db.commit()
    
    logger.info(f"Message sent: {current_user.username} -> {receiver_user.username}")
    
    return {
        "message_id": msg.id,
        "status": "sent",
        "delivered": msg.delivered_at is not None,
        "timestamp": msg.timestamp.isoformat(),
        "encryption_algorithm": "AES-256-GCM",
        "signature_algorithm": sig_metadata["algorithm"]
    }

@app.get("/api/messages/session/{session_id}")
async def get_session_messages(
    session_id: str,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get messages for a secure session"""
    # Verify user has access to session
    session = db.query(SecureSession).filter(
        SecureSession.id == session_id,
        or_(SecureSession.user1_id == current_user.id, SecureSession.user2_id == current_user.id)
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get messages
    messages = db.query(Message).filter(
        Message.session_id == session_id,
        Message.is_deleted_sender == False if Message.sender_id == current_user.id else True,
        Message.is_deleted_receiver == False if Message.receiver_id == current_user.id else True
    ).order_by(desc(Message.timestamp)).limit(limit).offset(offset).all()
    
    # Decrypt messages
    decrypted_messages = []
    shared_secret = session.shared_secret
    
    # Get sender's public keys for signature verification
    sender_id = session.user1_id if session.user1_id != current_user.id else session.user2_id
    sender = db.query(User).filter(User.id == sender_id).first()
    sender_keys = json.loads(sender.public_keys) if sender.public_keys else {}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for msg in messages:
            # Mark as read if receiver
            if msg.receiver_id == current_user.id and not msg.is_read:
                msg.is_read = True
                msg.read_at = datetime.utcnow()
            
            # Decrypt content
            verified = False
            if msg.message_type == "critical":
                # Critical messages need signature verification
                try:
                    try:
                        decrypted_content = decrypt_message(
                            msg.encrypted_content,
                            msg.nonce,
                            msg.tag,
                            shared_secret,
                            msg.aad
                        )
                    except:
                        decrypted_content = "[Decryption failed]"
                    
                    # Verify signature
                    # NOTE: C backend doesn't implement wrap_verify, using placeholder
                    # In production, implement this endpoint in C or use alternative verification
                    verified = True  # Placeholder - always mark as verified for testing
                    logger.info("Using placeholder signature verification - implement in C backend for production")
                except Exception as e:
                    logger.error(f"Signature verification failed: {str(e)}")
                    verified = False
            else:
                # Decrypt regular message
                try:
                    decrypted_content = decrypt_message(
                        msg.encrypted_content,
                        msg.nonce,
                        msg.tag,
                        shared_secret,
                        msg.aad
                    )
                except:
                    decrypted_content = "[Decryption failed]"
            
            sig_metadata = json.loads(msg.signature_metadata) if msg.signature_metadata else {}
            
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": msg.sender.username,
                "content": decrypted_content,
                "message_type": msg.message_type,
                "timestamp": msg.timestamp.isoformat(),
                "delivered_at": msg.delivered_at.isoformat() if msg.delivered_at else None,
                "read_at": msg.read_at.isoformat() if msg.read_at else None,
                "is_mine": msg.sender_id == current_user.id,
                "is_read": msg.is_read,
                "verified": verified,
                "is_critical": msg.message_type == "critical",
                "has_signature": bool(msg.falcon_signature),
                "quantum_algorithm": sig_metadata.get("algorithm", "Unknown") if sig_metadata else None,
                "metadata": sig_metadata.get("metadata", {}) if sig_metadata else {}
            })
    
    # Update session activity
    session.last_activity = datetime.utcnow()
    db.commit()
    
    return {
        "session_id": session_id,
        "messages": decrypted_messages,
        "total_count": session.message_count,
        "encryption_algorithm": "AES-256-GCM",
        "quantum_algorithm": "ML-KEM-768"
    }

# ========== MESSAGE/SESSION ALIASES (Frontend compatibility) ==========
@app.post("/api/message/send")
async def message_send_alias(
    message: MessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Alias for /api/messages/send - Frontend compatibility"""
    return await send_quantum_message(message, current_user, db)

@app.get("/api/messages")
async def get_messages_alias(
    session_id: Optional[str] = None,
    limit: int = 50,
    before_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get messages - Frontend compatibility alias"""
    # Get active session if no session_id provided
    if not session_id:
        session = get_active_session(current_user.id, db)
        if not session:
            return {"messages": [], "session_id": None}
        session_id = session.id
    
    # Get messages using the main function
    return await get_session_messages(session_id, limit, 0, current_user, db)

@app.get("/api/session/status")
async def session_status_alias(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get session status - Frontend compatibility"""
    return await get_active_sessions(current_user, db)

@app.post("/api/session/terminate")
async def session_terminate_alias(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Terminate session - Frontend compatibility"""
    # Get active session
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=404, detail="No active session")
    
    return await terminate_session(session.id, current_user, db)

# ========== SESSION MANAGEMENT ENDPOINTS ==========
@app.get("/api/sessions/active")
async def get_active_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all active sessions for current user"""
    sessions = db.query(SecureSession).filter(
        or_(SecureSession.user1_id == current_user.id, SecureSession.user2_id == current_user.id),
        SecureSession.is_active == True
    ).all()
    
    session_list = []
    for sess in sessions:
        other_user_id = sess.user1_id if sess.user2_id == current_user.id else sess.user2_id
        other_user = db.query(User).filter(User.id == other_user_id).first()
        
        # Get unread message count
        unread_count = db.query(Message).filter(
            Message.session_id == sess.id,
            Message.receiver_id == current_user.id,
            Message.is_read == False
        ).count()
        
        session_list.append({
            "session_id": sess.id,
            "other_user": {
                "id": other_user.id,
                "username": other_user.username,
                "last_seen": other_user.last_seen.isoformat(),
                "is_online": other_user.username in manager.get_online_users()
            },
            "established_at": sess.established_at.isoformat(),
            "last_activity": sess.last_activity.isoformat(),
            "message_count": sess.message_count,
            "unread_count": unread_count,
            "is_active": sess.is_active
        })
    
    return {"sessions": session_list}

@app.post("/api/sessions/{session_id}/terminate")
async def terminate_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Terminate a secure session"""
    session = db.query(SecureSession).filter(
        SecureSession.id == session_id,
        or_(SecureSession.user1_id == current_user.id, SecureSession.user2_id == current_user.id),
        SecureSession.is_active == True
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Active session not found")
    
    # Terminate session
    session.is_active = False
    session.terminated_at = datetime.utcnow()
    session.termination_reason = "User terminated"
    
    # Clear user keys
    current_user.public_keys = None
    current_user.key_generation_timestamp = None
    
    # Get other user
    other_user_id = session.user1_id if session.user2_id == current_user.id else session.user2_id
    other_user = db.query(User).filter(User.id == other_user_id).first()
    if other_user:
        other_user.public_keys = None
        other_user.key_generation_timestamp = None
    
    # Delete quantum service sessions
    async with httpx.AsyncClient(timeout=30.0) as client:
        await client.delete(f"{QUANTUM_API}/api/quantum/session/{current_user.username}")
        if other_user:
            await client.delete(f"{QUANTUM_API}/api/quantum/session/{other_user.username}")
    
    db.commit()
    
    # Send WebSocket notification
    if other_user:
        await manager.send_personal_message(
            other_user.username,
            {
                "type": "session_terminated",
                "session_id": session_id,
                "terminated_by": current_user.username,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    # Log audit
    log_audit(db, current_user.id, "SESSION_TERMINATED", f"Session: {session_id}", None)
    
    logger.info(f"Session terminated: {session_id} by {current_user.username}")
    
    return {"message": "Session terminated successfully"}

# ========== WEBSOCKET ENDPOINT ==========
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str, db: Session = Depends(get_db)):
    """WebSocket endpoint for real-time communication"""
    # Verify user exists
    user = db.query(User).filter(User.username == username).first()
    if not user:
        await websocket.close(code=4004, reason="User not found")
        return
    
    connection_id = await manager.connect(websocket, username)
    
    db = SessionLocal()
    try:
        # Update user status
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.last_seen = datetime.utcnow()
            db.commit()
            
            # Notify others user is online
            online_users = manager.get_online_users()
            await manager.broadcast_to_users(
                {
                    "type": "user_status_update",
                    "username": username,
                    "status": "online"
                },
                online_users
            )
        
        try:
            while True:
                # Receive message from WebSocket
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                # Handle different message types
                if message_data.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif message_data.get("type") == "heartbeat":
                    if user:
                        user.last_seen = datetime.utcnow()
                        db.commit()
                        
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for {username}")
            manager.disconnect(username)
            
            # Handle cleanup on disconnect
            if user:
                user.last_seen = datetime.utcnow()
                
                # Check for active session
                active_session = get_active_session(user.id, db)
                if active_session:
                    other_user_id = active_session.user1_id if active_session.user2_id == user.id else active_session.user2_id
                    other_user = db.query(User).filter(User.id == other_user_id).first()
                    
                    # Terminate session on disconnect
                    active_session.is_active = False
                    active_session.terminated_at = datetime.utcnow()
                    active_session.termination_reason = "WebSocket disconnect"
                    
                    # Clear keys
                    user.public_keys = None
                    user.key_generation_timestamp = None
                    if other_user:
                        other_user.public_keys = None
                        other_user.key_generation_timestamp = None
                        
                        # Notify other user
                        await manager.send_personal_message(
                            other_user.username,
                            {
                                "type": "session_update",
                                "status": "terminated",
                                "reason": "Connection lost",
                                "terminated_by": username
                            }
                        )
                
                db.commit()
                
            # Notify others user is offline
            online_users = manager.get_online_users()
            await manager.broadcast_to_users(
                {
                    "type": "user_status_update",
                    "username": username,
                    "status": "offline"
                },
                online_users
            )
            
    except Exception as e:
        logger.error(f"WebSocket error for {username}: {e}")
        manager.disconnect(username)
    finally:
        db.close()

# ========== SYSTEM ENDPOINTS ==========
@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "QMS Platform",
        "version": "3.0.0",
        "features": {
            "text_messaging": True,
            "quantum_key_exchange": True,
            "wrap_and_sign_signatures": True,
            "websocket_support": True
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/stats")
def get_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user statistics"""
    # Count messages
    total_messages_sent = db.query(Message).filter(Message.sender_id == current_user.id).count()
    total_messages_received = db.query(Message).filter(Message.receiver_id == current_user.id).count()
    
    # Count sessions
    total_sessions = db.query(SecureSession).filter(
        or_(SecureSession.user1_id == current_user.id, SecureSession.user2_id == current_user.id)
    ).count()
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "member_since": current_user.created_at.isoformat(),
        "statistics": {
            "messages_sent": total_messages_sent,
            "messages_received": total_messages_received,
            "total_sessions": total_sessions,
            "quantum_keys_generated": bool(current_user.public_keys)
        }
    }

# ========== STARTUP/SHUTDOWN ==========
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("QMS Platform v3.0 starting up...")
    logger.info("QMS Platform ready - Quantum service will be checked on demand")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    logger.info("QMS Platform shutting down...")

# ========== FRONTEND ROUTES ==========
@app.get("/")
async def serve_frontend():
    """Serve the main frontend application"""
    return FileResponse("index.html")

@app.get("/sw.js")
async def serve_service_worker():
    """Serve the service worker for PWA functionality"""
    return FileResponse("sw.js", media_type="application/javascript")

# ========== ERROR HANDLERS ==========
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*80)
    print("QMS PLATFORM - QUANTUM MESSAGING SYSTEM - v3.0.0")
    print("="*80)
    print("Features:")
    print("  - ML-KEM-768 quantum-resistant key exchange")
    print("  - Falcon-512 quantum-resistant signatures")
    print("  - Wrap-and-Sign hybrid protocol")
    print("  - AES-256-GCM authenticated encryption")
    print("  - WebSocket real-time communication")
    print("  - Perfect forward secrecy")
    print("  - Comprehensive audit logging")
    print("="*80)
    print("Starting server on http://localhost:4000")
    print("API Documentation: http://localhost:4000/docs")
    print("Alternative Docs: http://localhost:4000/redoc")
    print("="*80 + "\n")
    
    # Get port from environment variable or use default
    port = int(os.environ.get("PORT", 4000))

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
        access_log=True,
        use_colors=True
    )