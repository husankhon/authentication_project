# 🔐 Authentication API

A lightweight JWT-based authentication REST API built with **FastAPI**, **SQLModel**, and **SQLite**. It supports user registration, login, token refresh, and profile management with secure password hashing via Argon2.

---

## ✨ Features

- User registration with email validation and password constraints
- Secure password hashing with **Argon2** (via `pwdlib`)
- **JWT access tokens** (10-minute expiry) and **refresh tokens** (7-day expiry)
- Token refresh endpoint to issue new access tokens without re-login
- Protected `/me` endpoints to view and update your profile
- Timing-safe login (dummy hash verified on unknown emails to prevent timing attacks)
- SQLite database with **SQLModel** ORM
- Settings managed via `.env` file with **pydantic-settings**

---

## 🛠️ Tech Stack

| Layer         | Library                      |
|---------------|------------------------------|
| Framework     | FastAPI                      |
| ORM / DB      | SQLModel + SQLite            |
| Auth          | PyJWT (HS256)                |
| Hashing       | pwdlib (Argon2)              |
| Validation    | Pydantic v2 + email-validator|
| Config        | pydantic-settings            |
| Package Mgr   | uv                           |
| Python        | 3.14+                        |

---

## 📁 Project Structure

```
authentication/
├── main.py          # FastAPI app, routes, and dependency injection
├── models.py        # SQLModel table and schema definitions
├── database.py      # DB engine, session, and table creation
├── security.py      # Password hashing and JWT utilities
├── settings.py      # Environment variable loading
├── pyproject.toml   # Project metadata and dependencies
├── .env             # Secret environment variables (not committed)
└── auth.db          # SQLite database (auto-created on startup)
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd authentication
```

### 2. Install dependencies

This project uses [uv](https://docs.astral.sh/uv/) for package management.

```bash
uv sync
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```env
JWT_SECRET_KEY=your-super-secret-key-here
```

> [!CAUTION]
> Never commit your `.env` file. Use a strong, random secret key in production. Generate one with:
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

### 4. Run the server

```bash
uv run fastapi dev main.py
```

The API will be available at `http://127.0.0.1:8000`.  
Interactive docs: `http://127.0.0.1:8000/docs`

---

## 📡 API Endpoints

### Auth

| Method | Endpoint         | Auth Required | Description                        |
|--------|------------------|---------------|------------------------------------|
| `POST` | `/register`      | ❌            | Register a new user                |
| `POST` | `/token`         | ❌            | Login and receive access + refresh tokens |
| `POST` | `/token/refresh` | ❌            | Exchange a refresh token for a new access token |

### User

| Method  | Endpoint | Auth Required | Description               |
|---------|----------|---------------|---------------------------|
| `GET`   | `/me`    | ✅ Bearer     | Get the current user's profile |
| `PATCH` | `/me`    | ✅ Bearer     | Update the current user's email |

---

## 🔑 Authentication Flow

```
1. POST /register      → create account
2. POST /token         → get access_token + refresh_token
3. Use access_token    → Authorization: Bearer <access_token>
4. POST /token/refresh → get new access_token when it expires
```

> [!NOTE]
> Access tokens expire after **10 minutes**. Refresh tokens are valid for **7 days**.

---

## 📋 Request & Response Examples

### Register

```http
POST /register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secret123"
}
```

**Response `201`:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "role": "user"
}
```

> [!IMPORTANT]
> Password must be **8–12 characters** long.

### Login

```http
POST /token
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=secret123
```

**Response `200`:**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "bearer"
}
```

### Refresh Token

```http
POST /token/refresh
Content-Type: application/json

{
  "refresh_token": "<your-refresh-token>"
}
```

### Get Profile

```http
GET /me
Authorization: Bearer <access_token>
```

---

## ⚙️ Configuration Reference

| Variable        | Description                        | Required |
|-----------------|------------------------------------|----------|
| `JWT_SECRET_KEY`| Secret key used to sign JWT tokens | ✅ Yes   |

---

## 🧪 Development

Linting is configured with [Ruff](https://docs.astral.sh/ruff/) (import sorting enabled):

```bash
uv run ruff check .
uv run ruff check . --fix
```

