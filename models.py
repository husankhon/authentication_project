from sqlmodel import Field, SQLModel
from pydantic import EmailStr


class UserCreate(SQLModel):
    email: EmailStr 
    password: str = Field(min_length=8, max_length=12)




class User(SQLModel, table=True):
    __tablename__ = 'users'
    
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique = True)
    hashed_password: str
    role: str = Field(default = 'user')



class UserUpdate(SQLModel):
    email: EmailStr | None = None
    
class UserResponse(SQLModel):
    id: int
    email: str
    role: str