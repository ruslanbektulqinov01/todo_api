from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, select, desc
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()

SQLALCHEMY_DATABASE_URL = "postgresql+asyncpg://todo_admin:postgres@localhost/todo_db"

engine = create_async_engine(SQLALCHEMY_DATABASE_URL)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    tasks = relationship("Task", back_populates="owner", cascade="all, delete-orphan")


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, index=True)
    completed = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="tasks")


class TaskCreate(BaseModel):
    content: str


class TaskUpdate(BaseModel):
    content: Optional[str] = None
    completed: Optional[bool] = None


class TaskResponse(BaseModel):
    id: int
    content: str
    completed: bool

    class Config:
        from_orm = True


async def get_db():
    async with AsyncSessionLocal() as db:
        yield db


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    result = await db.execute(select(User).filter(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(SessionMiddleware, secret_key="your_secret_key")


@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == username))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit()
    return {"message": "User registered successfully"}


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...),
                db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    request.session["username"] = username
    return {"message": "Login successful"}


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "Logout successful"}


@app.get("/tasks", response_model=List[TaskResponse])
async def get_tasks(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Task).filter(Task.owner_id == user.id).order_by(Task.completed, desc(Task.id)))
    tasks = result.scalars().all()
    return tasks


@app.post("/tasks", response_model=TaskResponse)
async def add_task(task: TaskCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    new_task = Task(content=task.content, owner_id=user.id)
    db.add(new_task)
    await db.commit()
    await db.refresh(new_task)
    return new_task


@app.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
        task_id: int,
        task_update: TaskUpdate,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Task).filter(Task.id == task_id, Task.owner_id == user.id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    for key, value in task_update.dict(exclude_unset=True).items():
        setattr(task, key, value)

    await db.commit()
    await db.refresh(task)
    return task


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Task).filter(Task.id == task_id, Task.owner_id == user.id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await db.delete(task)
    await db.commit()
    return {"message": "Task deleted successfully"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
