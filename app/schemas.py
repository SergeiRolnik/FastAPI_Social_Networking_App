from datetime import date
from pydantic import BaseModel


# --- POST ---
class PostBase(BaseModel):
    content: str


class PostCreate(PostBase):
    pass


class Post(PostBase):
    id: int
    created_at: date
    likes: int
    dislikes: int
    user_id: int

    class Config:
        orm_mode = True


# --- USER ---
class UserBase(BaseModel):
    username: str


class UserCreate(UserBase):
    email: str
    password: str


class User(UserBase):
    id: int
    email: str
    posts: list[Post] = []

    class Config:
        orm_mode = True


# --- TOKEN ---
class Token(BaseModel):
    access_token: str
