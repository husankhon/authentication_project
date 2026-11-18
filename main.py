from database import SessionDep
from contextlib import asynccontextmanager
from typing import Annotated, Literal
from fastapi import FastAPI, status, HTTPException, Depends, Body, APIRouter
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from database import create_db_and_tables
from models import UserResponse, User, UserCreate, UserUpdate
from security import hash_password, verify_password, DUMMY_HASH, create_access_token, decode_token, create_refresh_token
from sqlmodel import select
from settings import settings

role = Literal['user', 'admin']

class RoleRequired():
    def __init__(self, roles: role):
        self.roles = roles
    
    def __call__(self, session: SessionDep, user: current_user):
        if user.role not in self.roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to perform this action")
        return user

oauth2_schema = OAuth2PasswordBearer(tokenUrl="token")

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


def get_current_user(session: SessionDep, token: Annotated[str, Depends(oauth2_schema)]):
    token_data = decode_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if token_data.get("type") == "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    email = token_data.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

current_user = Annotated[User, Depends(get_current_user)]


@app.post('/register', status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def register(session: SessionDep, user: UserCreate):
    existing_user = session.get(User, user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    new_user = User(email = user.email, hashed_password = hash_password(user.password))
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user
    

@app.post('/token')
def login(session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = session.exec(
        select(User).where(User.email == form_data.username)
    ).first()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Incorrect email or password",
        headers ={"WWW-Authenticate": "Bearer"}
        )
    if not user:
        verify_password(form_data.password, DUMMY_HASH)
        raise credentials_exception
    if not verify_password(form_data.password, user.hashed_password):
        raise credentials_exception
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    return {"access_token": access_token, 
            "refresh_token": refresh_token, 
            "token_type": "bearer"
            }

@app.post('/token/refresh')
def refresh_token(session: SessionDep, refresh_token: Annotated[str, Body(embed=True)]):
    payload = decode_token(refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    email = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    new_access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }
    

@app.get('/me', status_code=status.HTTP_200_OK, response_model=UserResponse)
def get_me(user: current_user):
    return user


@app.patch('/me', status_code=status.HTTP_200_OK, response_model=UserResponse)
def update_me(session: SessionDep, user: current_user, updated_user: UserUpdate):
    if not updated_user.email == user.email and session.get(User, updated_user.email):
        return user
    user_with_email = session.exec(
        select(User).where(User.email == updated_user.email)
    ).first()
    if user_with_email and user_with_email.email != user.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    user.email = updated_user.email
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
    
admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(RoleRequired(["admin"]))],
)

@admin_router.get('/users', status_code=status.HTTP_200_OK, response_model=list[UserResponse])
def get_users(session: SessionDep, user: current_user):
    return session.exec(select(User)).all()

@admin_router.delete('/users/{id}', status_code=status.HTTP_204_NO_CONTENT)
def delete_user(session: SessionDep, id: int):
    user_to_delete = session.get(User, id)
    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    session.delete(user_to_delete)
    session.commit()


app.include_router(admin_router)