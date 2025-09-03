# marketplace_backend.py
import secrets

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import logging
from typing import Optional
from enum import Enum

# config
DATABASE_URL = "sqlite:///./marketplace.db"
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# db 
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

#security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = declarative_base()

# logging setup
logging.basicConfig(level=logging.INFO)
logger = logging .getLogger(__name__)

# db models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    products = relationship("Product", back_populates="seller")
    purchases = relationship("Purchase", back_populates="buyer")


class CategoryEnum(str, Enum):
    SOFTWARE = "software"  # 0
    GAMES = "games"  # 1
    TOOLS = "tools"  # 2
    MEDIA = "media"  # 3
    EDUCATION = "education"  # 4

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    price = Column(Float)
    category = Column(String, index=True)
    seller_id = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    downloads = Column(Integer, default=0)
    rating = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    seller = relationship("User", back_populates="products")
    purchases = relationship("Purchase", back_populates="product")
    reviews = relationship("Review", back_populates="product")

class Purchase(Base):
    __tablename__ = "purchases"

    id = Column(Integer, primary_key=True, index=True)
    buyer_id = Column(Integer, ForeignKey("users.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    purchase_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    price_paid = Column(Float)

    buyer = relationship("User", back_populates="purchases")
    product = relationship("Product", back_populates="purchases")


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey("products.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Float)
    comment = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    product = relationship("Product", back_populates="reviews")
    user = relationship("User", back_populates="reviews")

# create tables
Base.metadata.create_all()

class UserCrate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str 
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True 

class Token(BaseModel):
    access_token: str
    token_type: str

class ProductCreate(BaseModel):
    title: str
    description: str
    price: float
    category: CategoryEnum

class ProductUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[CategoryEnum] = None
    is_active: Optional[bool] = None

class ProductResponse(BaseModel):
    id: int
    title: str
    description: str
    price: float
    category: CategoryEnum # or str
    is_active: bool
    downloads: int
    rating: float
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class PurchaseResponse(BaseModel):
    id: int
    product_id: int
    purchase_date: datetime
    price_paid: float

    class Config:
        from_attributes = True

class ReviewCreate(BaseModel):
    rating: int
    comment: str

class ReviewResponse(BaseModel):
    id: int
    user_id: int
    rating: int
    comment: str
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True

# fastAPI app
# fastAPI document ation: https://fastapi.tiangolo.com/

app = FastAPI(
    title="Marketplace API",
    description="Marketplace API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# auth utils
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta: 
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if  username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception        

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# API routes
@app.get("/")
async def root():
    return {"message": "$Welcome to the Marketplace API!"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    logger.info(f"Registration attempt for username: {user.username}")

    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    logger.info(f"User registered successfully: {user.username}")
    return db_user

@app.post("/login", response_model=Token)
def login_user(username: str, password: str, db: Session = Depends(get_db)):
    logger.info(f"LOgin attempt for username: {username}")

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        logger.warning(f"Failed login attempt for username: {username}")
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
            # headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    logger.info(f"Access token for username: {username}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/products", response_model=ProductResponse)
def create_product(product: ProductCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    logger.info(f"Creating product: {product.title} by user: {current_user.username}")

    db_product = Product(
        title=product.title,
        description=product.description,
        price=product.price,
        category=product.category.value,
        seller_id=current_user.id
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)

    logger.info(f"Product created successfully: {product.title}")
    return db_product

@app.get("/products", response_model=list[ProductResponse])
def list_products(
    skip: int = 0,
    limit: int = Query(default=50, lte=100),
    category: Optional[CategoryEnum] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Product).filter(Product.is_active == True)

    if category:
        query = query.filter(Product.category == category)
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)
    if search:
        query = query.filter(Product.title.contains(search))

    products = query.offset(skip).limit(limit).all()
    logger.info(f"Listed {len(products)} products with filters")
    return products

@app.get("/products/{product_id}", response_model=ProductResponse)
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id, Product.is_active == True).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product
@app.put("/products/{product_id}", response_model=ProductResponse)
def update_product(product_id: int, product_update: ProductUpdate, current_user: User = Depends(get_current_user),
    db: Session= Depends(get_db)
):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    if product.seller_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this product")

