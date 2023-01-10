from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta
import models
import schemas
from database import SessionLocal, engine
from passlib.context import CryptContext
from email_validator import validate_email, EmailNotValidError

tags_metadata = [
    {
        'name': 'Users',
        'description': 'User signup & login/get token'
    },
    {
        'name': 'Posts',
        'description': 'Create/view/update/delete & like/dislike posts'
    },
]

description = '''
This is a simple API that allows to do the following:
* User signup and login/get tokens
* Create/view/update/delete user posts
* Like/dislike posts
'''

app = FastAPI(
    openapi_tags=tags_metadata,
    title='Social Network App',
    description=description,
    version='0.0.1',
    contact={'name': 'the developer', 'email': 'Sergei.Rolnik@gmail.com'}
)

models.Base.metadata.create_all(bind=engine)
SECRET_KEY = 'd83ad20d7c390ba53fff45922fd8736569a4c8745e6e9ef71fa6ff1c2c98cd32'  # for production put in an env variable
ALGORITHM = 'HS256'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
pwd_context = CryptContext(schemes=['sha256_crypt'])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# generate token
def generate_token(user_id: int):
    token = jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=30)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return token


def get_current_user_id(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload['user_id']  # get current user id from token payload
    except JWTError:
        raise HTTPException(status_code=401, detail='Unable to validate user credentials')
    return user_id


# user signup (check if email is valid)
@app.post('/users/', tags=['Users'], response_model=schemas.User)
def user_signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail='Username already exists')
    try:
        validation = validate_email(user.email, check_deliverability=True)
        validated_email = validation.email
    except EmailNotValidError as error:
        raise HTTPException(status_code=400, detail=str(error))
    hashed_password = pwd_context.hash(user.password)
    new_user = models.User(username=user.username, email=validated_email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# get token
@app.post('/token/', tags=['Users'], response_model=schemas.Token)
def get_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    db_user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail='Username does not exist')
    if not pwd_context.verify(form_data.password, db_user.password):
        raise HTTPException(status_code=403, detail='Password incorrect')
    access_token = generate_token(db_user.id)
    return {'access_token': access_token, 'token_type': 'bearer'}


# create a post for a user
@app.post('/posts/', tags=['Posts'], response_model=schemas.Post)
def create_post_for_user(post: schemas.PostCreate,
                         db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    new_post = models.Post(**post.dict(), user_id=current_user_id)
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    return new_post


# get all posts
@app.get("/posts/", tags=['Posts'], response_model=list[schemas.Post])
def get_all_posts(db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    posts = db.query(models.Post).all()
    return posts


# get current user's posts
@app.get("/posts/mine/", tags=['Posts'], response_model=list[schemas.Post])
def get_my_posts(db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    posts = db.query(models.Post).filter(models.Post.user_id == current_user_id).all()
    return posts


# view a post
@app.get("/posts/{post_id}", tags=['Posts'], response_model=schemas.Post)
def get_post(post_id: int, db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail='Post not found')
    return post


# update a post
@app.patch("/posts/{post_id}", tags=['Posts'], response_model=schemas.Post)
def update_post(post_id: int, post_data: schemas.PostCreate,
                db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail='Post not found')
    if post.user_id == current_user_id:
        post = db.query(models.Post).get(post_id)
        post.content = post_data.dict()['content']  # let's assume that only content field can be updated
        db.add(post)
        db.commit()
        return post
    else:
        raise HTTPException(status_code=400, detail='You can only update your own posts')


# delete a post
@app.delete("/posts/{post_id}", tags=['Posts'], response_model=schemas.Post)
def delete_post(post_id: int,
                db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail='Post not found')
    if post.user_id == current_user_id:
        db.delete(post)
        db.commit()
        return post
    else:
        raise HTTPException(status_code=400, detail='You can only delete your own posts')


# like a post
@app.patch("/posts/{post_id}/like/", tags=['Posts'], response_model=schemas.Post)
def like_post(post_id: int,
              db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail='Post not found')
    if post.user_id == current_user_id:
        raise HTTPException(status_code=400, detail='You cannot like your own posts')
    post.likes += 1
    db.commit()
    return post


# dislike a post
@app.patch("/posts/{post_id}/dislike/", tags=['Posts'], response_model=schemas.Post)
def dislike_post(post_id: int,
                 db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail='Post not found')
    if post.user_id == current_user_id:
        raise HTTPException(status_code=400, detail='You cannot dislike your own posts')
    post.dislikes += 1
    db.commit()
    return post
