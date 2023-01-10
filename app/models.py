from sqlalchemy import Column, ForeignKey, Integer, String, Date
from sqlalchemy.orm import relationship
from database import Base
from datetime import date


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String)
    password = Column(String)
    posts = relationship('Post', backref='users')


class Post(Base):
    __tablename__ = 'posts'
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    created_at = Column(Date, default=date.today())
    likes = Column(Integer, default=0)
    dislikes = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey('users.id'))
