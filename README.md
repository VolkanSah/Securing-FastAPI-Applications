# Securing FastAPI Applications
### A Comprehensive Guide to Building Secure APIs with FastAPI
###### server security guide by volkansah

FastAPI is a modern, high-performance web framework for building APIs with Python. While its speed and developer-friendly syntax make it an excellent choice, securing your application properly is crucial.

This guide covers key areas of API security, including authentication, input validation, HTTPS, and more. Each section includes examples and tools to help you apply best practices in real-world applications.

## Table of Contents
1. [Authentication and Authorization](#1-authentication-and-authorization)
2. [Input Validation and Sanitization](#2-input-validation-and-sanitization)
3. [SQL Injection Prevention](#3-sql-injection-prevention)
4. [Password Security](#4-password-security)
5. [CSRF Protection](#5-csrf-protection)
6. [HTTPS (TLS/SSL)](#6-https-tlsssl)
7. [Secure Headers](#7-secure-headers)
8. [Rate Limiting](#8-rate-limiting)
9. [CORS (Cross-Origin Resource Sharing)](#9-cross-origin-resource-sharing-cors)
10. [Session Management](#10-session-management)
11. [Secrets Management](#11-secrets-management)
12. [Data Encryption](#12-data-encryption)
13. [Error Handling](#13-error-handling)
14. [File Upload Security](#14-file-upload-security)
15. [Database Security](#15-database-security)
16. [Logging and Monitoring](#16-logging-and-monitoring)
17. [Static File Handling](#17-static-file-handling)
18. [Dependency Injection](#18-dependency-injection)
19. [Dependency Management](#19-dependency-management)
20. [Security Best Practices](#20-security-best-practices)
21. [Advanced Protections](#21-advanced-protections)
22. [Checklist for Deployment](#checklist-for-deployment)

---

### 1. **Authentication and Authorization**
- **Authentication**: Ensure users can securely authenticate. Use libraries like `OAuth2`, `JWT` (JSON Web Tokens), or API keys.
    - FastAPI has built-in support for OAuth2 and JWT integration.
    - Use `fastapi.security` to define OAuth2 token flow.
- **Authorization**: Control access to resources based on user roles or permissions.
    - Use dependency injection to enforce access rules at the endpoint level.

**Example with proper JWT validation**:
```python
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = "your-secret-key-keep-it-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
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
    except JWTError:
        raise credentials_exception
    return {"username": username}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Verify user credentials here
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/secure-endpoint")
def secure_endpoint(user: dict = Depends(get_current_user)):
    return {"message": f"Hello, {user['username']}!"}
```

---

### 2. **Input Validation and Sanitization**
- Validate all inputs using Pydantic models to prevent injection attacks and ensure data consistency.
- Use field validators for additional security checks.

**Example of a Pydantic model with validation**:
```python
from pydantic import BaseModel, Field, validator
import re

class UserInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    age: int = Field(..., ge=0, le=150)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match("^[a-zA-Z0-9_]+$", v):
            raise ValueError('Username must be alphanumeric')
        return v
    
    @validator('email')
    def email_valid(cls, v):
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", v):
            raise ValueError('Invalid email format')
        return v
```

---

### 3. **SQL Injection Prevention**
- Always use ORM (Object-Relational Mapping) like SQLAlchemy with parameterized queries.
- Never concatenate user input directly into SQL queries.

**Example with SQLAlchemy**:
```python
from sqlalchemy.orm import Session
from sqlalchemy import select

# GOOD - Parameterized query
def get_user_safe(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

# BAD - Never do this!
# query = f"SELECT * FROM users WHERE username = '{username}'"
```

---

### 4. **Password Security**
- Never store passwords in plain text.
- Use strong hashing algorithms like `bcrypt` or `argon2`.

**Example**:
```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
```

---

### 5. **CSRF Protection**
- Implement CSRF tokens for state-changing operations.
- Use the `fastapi-csrf-protect` library.

**Example**:
```python
from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel

class CsrfSettings(BaseModel):
    secret_key: str = "your-secret-key"

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()

@app.post("/form-submit")
async def submit_form(csrf_protect: CsrfProtect = Depends()):
    await csrf_protect.validate_csrf_in_cookies(request)
    return {"message": "Form submitted successfully"}
```

---

### 6. **HTTPS (TLS/SSL)**
- Always serve your API over HTTPS to encrypt data in transit.
- Use tools like Let's Encrypt for free TLS certificates.
- Configure your web server (e.g., Nginx or Uvicorn) to redirect HTTP to HTTPS.

**Nginx configuration example**:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

---

### 7. **Secure Headers**
- Use security headers to protect your API from common attacks like XSS, clickjacking, etc.
- Implement Content Security Policy (CSP).

**Example**:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["yourdomain.com", "*.yourdomain.com"])
app.add_middleware(HTTPSRedirectMiddleware)
```

---

### 8. **Rate Limiting**
- Implement rate limiting to prevent abuse or brute-force attacks.
- Use tools like `slowapi`:

```bash
pip install slowapi
```

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Request

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/")
@limiter.limit("5/minute")
async def home(request: Request):
    return {"message": "Welcome!"}
```

---

### 9. **Cross-Origin Resource Sharing (CORS)**
- Restrict which domains can interact with your API.
- Only allow trusted origins in production.

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Don't use ["*"] in production!
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)
```

---

### 10. **Session Management**
- Implement proper session timeout and token expiration.
- Use secure session storage (Redis, database).
- Implement token refresh mechanism.

**Example**:
```python
from datetime import datetime, timedelta

ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

def create_tokens(user_id: str):
    access_token = create_access_token(
        data={"sub": user_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_access_token(
        data={"sub": user_id, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    return {"access_token": access_token, "refresh_token": refresh_token}
```

---

### 11. **Secrets Management**
- Never hardcode secrets in your code.
- Use environment variables with `.env` files (development only).
- Use proper secret management in production (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
- Implement secret rotation.

**Example with python-dotenv**:
```python
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")
```

**`.gitignore` must include**:
```
.env
.env.local
.env.*.local
secrets/
*.key
*.pem
```

---

### 12. **Data Encryption**
- Encrypt sensitive data at rest using libraries like `cryptography`.
- Encrypt data in transit with HTTPS/TLS.

**Example**:
```python
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_data(data: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()
```

---

### 13. **Error Handling**
- Never expose sensitive information in error messages.
- Don't show stack traces in production.
- Use generic error messages for users.

**Example**:
```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

app = FastAPI()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Log the detailed error internally
    print(f"Validation error: {exc}")
    # Return generic message to user
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Invalid input data"}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Log the error
    print(f"Internal error: {exc}")
    # Don't expose internal details
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )
```

---

### 14. **File Upload Security**
- Validate file types and sizes.
- Scan uploaded files for malware.
- Store files outside the web root.
- Use unique filenames to prevent overwrites.

**Example**:
```python
from fastapi import UploadFile, File, HTTPException
import magic
import uuid
from pathlib import Path

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # Check file size
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")
    
    # Check file type
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    # Verify MIME type
    mime = magic.from_buffer(contents, mime=True)
    if not mime.startswith('image/') and mime != 'application/pdf':
        raise HTTPException(status_code=400, detail="Invalid file content")
    
    # Save with unique filename
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = Path("uploads") / unique_filename
    
    with open(file_path, "wb") as f:
        f.write(contents)
    
    return {"filename": unique_filename}
```

---

### 15. **Database Security**
- Use encrypted connection strings.
- Apply principle of least privilege for database users.
- Implement connection pooling with limits.
- Regular database backups with encryption.

**Example with SQLAlchemy**:
```python
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

DATABASE_URL = "postgresql://user:password@localhost/dbname?sslmode=require"

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # Verify connections before using
    echo=False  # Don't log SQL in production
)
```

---

### 16. **Logging and Monitoring**
- Log security events (failed logins, suspicious activities).
- Never log sensitive data (passwords, tokens, credit cards).
- Use structured logging.
- Implement monitoring and alerting.

**Example**:
```python
import logging
from pythonjsonlogger import jsonlogger

logger = logging.getLogger()

logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info("request_started", extra={
        "method": request.method,
        "path": request.url.path,
        "ip": request.client.host
    })
    response = await call_next(request)
    logger.info("request_completed", extra={
        "status_code": response.status_code
    })
    return response
```

**Tools**:
- Error tracking: Sentry, Rollbar
- Monitoring: Prometheus, Grafana, Datadog
- Logging: ELK Stack, Splunk

---

### 17. **Static File Handling**
- Be cautious when serving static files.
- Never expose sensitive files (.env, .git, config files).
- Set proper permissions and access controls.

**Example**:
```python
from fastapi.staticfiles import StaticFiles
import os

# Ensure directory exists and has proper permissions
static_dir = "static"
if not os.path.exists(static_dir):
    os.makedirs(static_dir, mode=0o755)

app.mount("/static", StaticFiles(directory=static_dir), name="static")
```

---

### 18. **Dependency Injection**
- Use FastAPI's dependency injection for security checks.
- Create reusable security dependencies.

**Example**:
```python
from fastapi import Depends, HTTPException

def verify_api_key(api_key: str = Header(...)):
    if api_key != "expected-api-key":
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

def check_admin_role(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(check_admin_role)):
    # Only admins can access this endpoint
    return {"message": f"User {user_id} deleted by {admin['username']}"}
```

---

### 19. **Dependency Management**
- Keep all dependencies up to date.
- Regularly scan for vulnerabilities.
- Use dependency pinning in production.

**Tools**:
```bash
# Install security scanning tools
pip install pip-audit safety bandit

# Run security scans
pip-audit
safety check
bandit -r app/

# Use requirements.txt with pinned versions
pip freeze > requirements.txt
```

**GitHub Dependabot configuration** (`.github/dependabot.yml`):
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

---

### 20. **Security Best Practices**
- Follow the principle of least privilege.
- Implement defense in depth (multiple security layers).
- Regular security audits and penetration testing.
- Keep FastAPI and all dependencies updated.
- Use security linters and static analysis tools.
- Document security policies and procedures.

**Additional Security Measures**:
- API versioning for backward compatibility
- Protection against XXE (XML External Entity) attacks
- SSRF (Server-Side Request Forgery) prevention
- WebSocket security (if applicable)

---

### 21. **Advanced Protections**
- Implement Web Application Firewall (WAF) rules.
- Consider API gateways like Kong, AWS API Gateway, or Azure API Management.
- Use DDoS protection services.
- Implement intrusion detection systems (IDS).

**Example WAF rules with ModSecurity**:
```
# Block common SQL injection patterns
SecRule ARGS "@rx (union.*select|insert.*into)" "id:1,deny,status:403"

# Block XSS attempts
SecRule ARGS "@rx (<script|javascript:)" "id:2,deny,status:403"
```

---

## Checklist for Deployment

Before you deploy your FastAPI application to production, make sure you've checked the following boxes:

### 🔐 **Security**

- [ ] **Authentication implemented** (OAuth2 / JWT / API Keys)
- [ ] **Authorization rules enforced** (role-based / permissions)
- [ ] **Password hashing active** (bcrypt / argon2)
- [ ] **JWT token validation implemented** (not just mock checks)
- [ ] **Token expiration and refresh configured**
- [ ] **Session management secure** (timeout, secure storage)
- [ ] **Rate limiting active** (`slowapi` or via reverse proxy)
- [ ] **CORS configured properly** (only allow trusted domains, no `*` in production)
- [ ] **CSRF protection enabled** for state-changing operations
- [ ] **Security headers enabled** (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- [ ] **HTTPS/TLS enabled** (via Nginx, Caddy, or cloud provider)
- [ ] **HTTP to HTTPS redirect configured**
- [ ] **Input validation implemented** (Pydantic models with validators)
- [ ] **SQL injection prevention** (ORM usage, parameterized queries)
- [ ] **XSS protection in place**
- [ ] **Static file permissions checked** (no `.env` or secrets exposed)
- [ ] **File upload security** (type validation, size limits, virus scanning)
- [ ] **API versioning implemented**

### 🔑 **Secrets & Configuration**

- [ ] **No hardcoded secrets in code**
- [ ] **Environment variables protected** (`.env` for dev, proper secrets manager for prod)
- [ ] **`.gitignore` includes all sensitive files** (`.env`, `*.key`, `*.pem`, etc.)
- [ ] **Secret rotation strategy defined**
- [ ] **Database credentials encrypted**
- [ ] **API keys stored securely**

### 🛡️ **Code & Dependency Safety**

- [ ] **All packages up-to-date**
- [ ] **Security scan run** (`bandit`, `pip-audit`, `safety`)
- [ ] **Dependencies pinned** in `requirements.txt`
- [ ] **Dependabot or Renovate configured**
- [ ] **No known vulnerabilities in dependencies**
- [ ] **Remove debug endpoints or dev routes**
- [ ] **Debug mode disabled** (`debug=False`)

### 💾 **Database Security**

- [ ] **Database connections encrypted** (SSL/TLS)
- [ ] **Least privilege database user**
- [ ] **Connection pooling configured with limits**
- [ ] **Database backups automated and encrypted**
- [ ] **Database credentials not in version control**

### 🚨 **Error Handling & Logging**

- [ ] **Error tracking active** (e.g., Sentry, Rollbar)
- [ ] **Application logs enabled** (structured logging preferred)
- [ ] **Sensitive data not logged** (passwords, tokens, PII)
- [ ] **Generic error messages for users** (no stack traces exposed)
- [ ] **Security events logged** (failed logins, suspicious activity)

### 📊 **Monitoring & Alerts**

- [ ] **Performance monitoring** (e.g., Prometheus, Grafana, Datadog)
- [ ] **Alerts configured** for critical errors or traffic spikes
- [ ] **Health check endpoints exist** (`/health`, `/ready`)
- [ ] **Uptime monitoring configured**

### 🚀 **Deployment Readiness**

- [ ] **Dockerized or virtualized properly**
- [ ] **Gunicorn/Uvicorn workers configured** (multiple workers for production)
- [ ] **Reverse proxy configured** (Nginx, Caddy, Traefik)
- [ ] **Load balancer configured** (if applicable)
- [ ] **CI/CD pipeline tested** (GitHub Actions, GitLab CI, etc.)
- [ ] **Deployment rollback strategy defined**
- [ ] **Resource limits configured** (CPU, memory)

### 🌐 **Infrastructure Security**

- [ ] **Firewall rules configured**
- [ ] **Only necessary ports open**
- [ ] **WAF configured** (if applicable)
- [ ] **DDoS protection enabled**
- [ ] **Network segmentation implemented**
- [ ] **Regular security patches applied to servers**

### 🧪 **Testing**

- [ ] **Manual test of all endpoints done**
- [ ] **Auth flow tested end-to-end**
- [ ] **Edge cases handled** (token expiry, invalid inputs, etc.)
- [ ] **404/500 fallback routes implemented**
- [ ] **Security testing performed** (OWASP Top 10)
- [ ] **Penetration testing done** (if applicable)
- [ ] **Load testing performed**

### 📋 **Documentation & Compliance**

- [ ] **API documentation generated** (OpenAPI/Swagger)
- [ ] **Security policies documented**
- [ ] **Incident response plan defined**
- [ ] **GDPR/privacy compliance checked** (if applicable)
- [ ] **Terms of service and privacy policy published**

### 🔄 **Post-Deployment**

- [ ] **Monitoring dashboards set up**
- [ ] **On-call rotation defined**
- [ ] **Backup restoration tested**
- [ ] **Disaster recovery plan documented**
- [ ] **Regular security audits scheduled**

---

📌 **Pro tip**: Save this checklist as `DEPLOYMENT.md` in your repo and tick the boxes during your review. Consider using tools like [GitHub issue templates](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository) for deployment checklists.

---

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

## License

This guide is released under the MIT License. See LICENSE file for details.

---

**If you found this guide useful, don't forget to ⭐ the repo!**

###### Created by [VolkanSah](https://github.com/volkansah)
