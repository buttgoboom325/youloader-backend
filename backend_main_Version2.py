import os
import subprocess
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime, timedelta

# ====== CONFIG ======
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ADMIN_USERNAME = "admin"

# ====== IN-MEMORY "DATABASE" ======
users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": None,  # To be set at runtime
        "is_admin": True,
    }
}

# ====== SECURITY UTILS ======
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = users_db.get(username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

def get_current_admin(current_user=Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return current_user

# ====== FASTAPI APP ======
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; restrict for production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserRegister(BaseModel):
    username: str
    password: str

class DownloadRequest(BaseModel):
    url: str
    format: str  # "audio" or "video"

@app.post("/register")
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already taken")
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": get_password_hash(user.password),
        "is_admin": False,
    }
    return {"msg": "User registered"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    access_token = create_access_token(
        data={"sub": user["username"], "admin": user["is_admin"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/download")
def download(req: DownloadRequest, current_user=Depends(get_current_user)):
    url = req.url
    ftype = req.format
    if ftype not in ("audio", "video"):
        raise HTTPException(status_code=400, detail="Bad format")
    outtmpl = f"downloads/{current_user['username']}_%(id)s.%(ext)s"
    os.makedirs("downloads", exist_ok=True)

    if ftype == "audio":
        ytdlp_cmd = [
            "yt-dlp", "-f", "bestaudio", "--extract-audio", "--audio-format", "mp3",
            "-o", outtmpl, url
        ]
    else:
        ytdlp_cmd = [
            "yt-dlp", "-f", "best", "-o", outtmpl, url
        ]

    # Run yt-dlp
    try:
        result = subprocess.run(ytdlp_cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {e.stderr}")

    # Find downloaded file
    for fname in os.listdir("downloads"):
        if fname.startswith(current_user["username"]):
            filepath = os.path.join("downloads", fname)
            return FileResponse(filepath, filename=fname, media_type="application/octet-stream")
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/me")
def get_me(current_user=Depends(get_current_user)):
    return {"username": current_user["username"], "is_admin": current_user["is_admin"]}

# === ADMIN ENDPOINTS ===
@app.get("/admin/users")
def admin_users(admin=Depends(get_current_admin)):
    return [u for u in users_db if u != "admin"]

@app.post("/admin/set-admin")
def set_admin(user: str, admin=Depends(get_current_admin)):
    if user not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    users_db[user]["is_admin"] = True
    return {"msg": "User promoted"}

# ====== INIT ADMIN PASSWORD (for demo) ======
if users_db["admin"]["hashed_password"] is None:
    users_db["admin"]["hashed_password"] = get_password_hash("adminpass")