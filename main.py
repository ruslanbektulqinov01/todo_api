from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel

app = FastAPI()

# === Config ===

SQLALCHEMY_DATABASE_URL = "sqlite:///./todo.db"

# === Database setup ===

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# === Models ===

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    tasks = relationship("Task", back_populates="owner")


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, index=True)
    completed = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="tasks")


Base.metadata.create_all(bind=engine)


# === Pydantic Models (for request/response validation) ===

class TaskCreate(BaseModel):
    content: str


class TaskUpdate(BaseModel):
    content: str | None = None
    completed: bool | None = None


# === Dependencies ===

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


# === Password hashing ===

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === Middleware ===

app.add_middleware(SessionMiddleware, secret_key="your_secret_key")


# === Routes ===

# Register a new user
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_password = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}


# Login
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    request.session["username"] = username
    return {"message": "Login successful"}


# Logout
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "Logout successful"}


# Get all tasks for the current user
@app.get("/tasks")
async def get_tasks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tasks = db.query(Task).filter(Task.owner_id == user.id).order_by(Task.completed, desc(Task.id)).all()
    return {"tasks": tasks}


# Add a new task for the current user
@app.post("/tasks")
async def add_task(task: TaskCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_task = Task(content=task.content, owner_id=user.id)
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return {"success": True, "task": new_task}


# Update a task
@app.put("/tasks/{task_id}")
async def update_task(
        task_id: int,
        task_update: TaskUpdate,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    task = db.query(Task).filter(Task.id == task_id, Task.owner_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task_update.content is not None:
        task.content = task_update.content
    if task_update.completed is not None:
        task.completed = task_update.completed

    db.commit()
    return {"success": True, "task": task}


# Delete a task
@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id, Task.owner_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete(task)
    db.commit()
    return {"success": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
