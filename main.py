import bcrypt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase
import os
import re
import smtplib
import random
import string
from email.mime.text import MIMEText

# Use /app/data in Docker, ./data locally
DB_DIR = os.environ.get("DB_DIR", "./data")
os.makedirs(DB_DIR, exist_ok=True)
DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'users.db')}"

SECRET_KEY = os.environ.get("SECRET_KEY", "mysecretkey123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = "30"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    is_activate = Column(Boolean, default=True)

class OTP(Base):
    __tablename__ = "otp"

    id = Column(Integer, primary_key=True)
    email = Column(String)
    code = Column(String)
    purpose = Column(String)
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)
    username = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=20)
    email: str
    password: str = Field(min_length=6)

    @validator("username")
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username must be alphanumeric with underscores only")
        return v

    @validator("email")
    def validate_email(cls, v):
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
            raise ValueError("Invalid email format")
        return v

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ForgotPasswordVerifyRequest(BaseModel):
    email: str
    otp: str
    new_password: str = Field(min_length=6)

class VerifyRegisterRequest(BaseModel):
    email: str
    otp: str

# Hardcoded SMTP config
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "ashutoshknp12@gmail.com"
SMTP_PASS = "jexv miua iqsr snvk"
SMTP_SENDER = "ashutoshknp12@gmail.com"

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(to_email, otp_code, purpose):
    if purpose == "register":
        subject = "Verify Your Account"
    elif purpose == "forgot_password":
        subject = "Password Reset Code"
    else:
        subject = "Your OTP Code"
    body = f"Your OTP code is: {otp_code}\nIt expires in 5 minutes."
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_SENDER
    msg["To"] = to_email
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_SENDER, to_email, msg.as_string())
        server.quit()
        return True
    except Exception:
        return False

def create_otp(db, email, purpose):
    code = generate_otp()
    otp = OTP(
        email=email,
        code=code,
        purpose=purpose,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.add(otp)
    db.commit()
    return code

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_access_token(data):
    to_encode = data.copy()
    to_encode["sub"] = str(to_encode["sub"])
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["type"] = "access"
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data):
    to_encode = data.copy()
    to_encode["sub"] = str(to_encode["sub"])
    to_encode["exp"] = datetime.utcnow() + timedelta(days=7)
    to_encode["type"] = "refresh"
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        token_type = payload.get("type")
        if user_id is None or token_type != "access":
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


app = FastAPI()

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://frontend-15-two.vercel.app,https://frontend-15-b3jpt0vcu-ashutoshs-projects-8cd9906b.vercel.app,http://localhost:5173,http://localhost:5174,http://localhost:7860").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

@app.post("/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Username taken")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Email already registered")
    code = generate_otp()
    otp = OTP(
        email=req.email,
        code=code,
        purpose="register",
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        username=req.username,
        password_hash=hash_password(req.password)
    )
    db.add(otp)
    db.commit()
    send_otp_email(req.email, code, "register")
    return {"message": "OTP sent to email. Verify to activate account."}

@app.post("/auth/register/verify")
def register_verify(req: VerifyRegisterRequest, db: Session = Depends(get_db)):
    otp = db.query(OTP).filter(
        OTP.email == req.email,
        OTP.code == req.otp,
        OTP.purpose == "register",
        OTP.is_used == False
    ).first()
    if not otp:
        raise HTTPException(400, "Invalid OTP")
    if otp.expires_at < datetime.utcnow():
        raise HTTPException(400, "OTP expired")
    user = User(
        username=otp.username,
        email=otp.email,
        password=otp.password_hash,
        is_activate=True
    )
    db.add(user)
    otp.is_used = True
    db.commit()
    return {"message": "Account verified. You can now login."}

@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        (User.username == req.username) | (User.email == req.username)
    ).first()
    if not user or not verify_password(req.password, user.password):
        raise HTTPException(401, "Wrong credentials")
    if not user.is_activate:
        raise HTTPException(401, "Account not verified. Check your email for OTP.")
    return {
        "access_token": create_access_token({"sub": user.id}),
        "refresh_token": create_refresh_token({"sub": user.id})
    }

@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username, "email": current_user.email}

@app.post("/auth/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(req.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token")
        user_id = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(401, "Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(401, "User not found")
    
    if not user.is_activate:
        raise HTTPException(401, "User deactivated")
    
    new_refresh_token = create_refresh_token({"sub": user.id})
    
    return {
        "access_token": create_access_token({"sub": user.id}),
        "refresh_token": new_refresh_token
    }

@app.post("/users")
def create_user(
    req: RegisterRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Username taken")
    user = User(
        username=req.username,
        email=req.email,
        password=hash_password(req.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "email": user.email}

@app.get("/users")
def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(User).all()

@app.get("/users/{user_id}")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/users/{user_id}")
def update_user(
    user_id: int,
    username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.username = username
    db.commit()
    return user

@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "Deleted"}

@app.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(404, "Email not found")
    code = create_otp(db, req.email, "forgot_password")
    send_otp_email(req.email, code, "forgot_password")
    return {"message": "OTP sent to email"}

@app.post("/auth/forgot-password/verify")
def forgot_password_verify(req: ForgotPasswordVerifyRequest, db: Session = Depends(get_db)):
    otp = db.query(OTP).filter(
        OTP.email == req.email,
        OTP.code == req.otp,
        OTP.purpose == "forgot_password",
        OTP.is_used == False
    ).first()
    if not otp:
        raise HTTPException(400, "Invalid OTP")
    if otp.expires_at < datetime.utcnow():
        raise HTTPException(400, "OTP expired")
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.password = hash_password(req.new_password)
    otp.is_used = True
    db.commit()
    return {"message": "Password reset successful"}
