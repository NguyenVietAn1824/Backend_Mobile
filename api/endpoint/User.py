from typing import Annotated
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Response, Cookie
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4
from pydantic import ValidationError
import models.User
from schemas import User
from dependencies.dependencies import get_db
import schemas, models
from core.hash import get_password_hash, verify_password
from core.jwt import (
    create_token_pair,
    refresh_token_state,
    decode_access_token,
    mail_token,
    add_refresh_token_cookie,
    SUB,
    JTI,
    EXP,
)
from exceptions.exceptions import BadRequestException, NotFoundException, ForbiddenException
from core.task import (
    user_mail_event,
)
import schemas.User

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


async def create_user(db: AsyncSession, user_data: dict):
    try:
        user = models.User.User(**user_data)
        user.is_active = False
        db.add(user)
        db.commit()
        print("Thêm user thành công")
        db.refresh(user)
        print("Success tạo user")
        print(f"User email: {user.email}")
        print(f"User id: {user.id}")
        print(f"User is_active: {user.is_active}")
    except Exception as e:
        await db.rollback()
        print("Error khi tạo user:", e)
        raise
    return user

@router.post("/register", response_model=User.User)
async def register(
    data: User.UserRegister,
    bg_task: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    user = await models.User.User.find_by_email(db=db, email=data.email) ## Tìm email nếu đã tồn tại trong db thì trả về đã đăng kí
    if user:
        raise HTTPException(status_code=400, detail="Email has already registered")

    # hashing password
    user_data = data.dict(exclude={"confirm_password"}) ## Lấy dữ liệu từ data trừ confirm_password
    user_data["password"] = get_password_hash(user_data["password"])
    
    # save user to db
    try:
        user = await create_user(db, user_data)
        print(f"User created: {user.email}")
    except Exception as e:
        print("BUggggg")
    # send verify email
    user_schema = User.User.model_validate(user)
    verify_token = mail_token(user_schema) ## Tạo mail token

    mail_task_data = User.MailTaskSchema(
        user=user_schema, body= User.MailBodySchema(type="verify", token=verify_token)
    )
    bg_task.add_task(user_mail_event, mail_task_data)

    return user_schema


@router.post("/login")
async def login(
    data: schemas.User.UserLogin,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    user = await models.User.User.authenticate(
        db=db, email=data.email, password=data.password
    )

    if not user:
        raise BadRequestException(detail="Email hoặc mật khẩu không chính xác")

    if not user.is_active:
        raise ForbiddenException(detail="Tài khoản chưa được kích hoạt")

    # Thay from_orm bằng model_validate
    user_schema = schemas.User.User.model_validate(user)
    token_pair = create_token_pair(user=user_schema)
    add_refresh_token_cookie(response=response, token=token_pair.refresh.token)

    return {"token": token_pair.access.token}


# @router.post("/refresh")
# async def refresh(refresh: Annotated[str | None, Cookie()] = None):
#     print(refresh)
#     if not refresh:
#         raise BadRequestException(detail="refresh token required")
#     return refresh_token_state(token=refresh)


# @router.get("/verify", response_model=schemas.SuccessResponseScheme)
# async def verify(token: str, db: AsyncSession = Depends(get_db)):
#     payload = await decode_access_token(token=token, db=db)
#     user = await models.User.find_by_id(db=db, id=payload[SUB])
#     if not user:
#         raise NotFoundException(detail="User not found")
@router.post("/login")
async def login(
    data: schemas.User.UserLogin,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    user = await models.User.User.authenticate(
        db=db, email=data.email, password=data.password
    )

    if not user:
        raise BadRequestException(detail="Email hoặc mật khẩu không chính xác")

    if not user.is_active:
        raise ForbiddenException(detail="Tài khoản chưa được kích hoạt")

    # Thay from_orm bằng model_validate
    user_schema = schemas.User.User.model_validate(user)
    token_pair = create_token_pair(user=user_schema)
    add_refresh_token_cookie(response=response, token=token_pair.refresh.token)

    return {"token": token_pair.access.token}    @router.post("/login")
    async def login(
        data: schemas.User.UserLogin,
        response: Response,
        db: AsyncSession = Depends(get_db),
    ):
        user = await models.User.User.authenticate(
            db=db, email=data.email, password=data.password
        )
    
        if not user:
            raise BadRequestException(detail="Email hoặc mật khẩu không chính xác")
    
        if not user.is_active:
            raise ForbiddenException(detail="Tài khoản chưa được kích hoạt")
    
        # Thay from_orm bằng model_validate
        user_schema = schemas.User.User.model_validate(user)
        token_pair = create_token_pair(user=user_schema)
        add_refresh_token_cookie(response=response, token=token_pair.refresh.token)
    
        return {"token": token_pair.access.token}        @router.post("/login")
        async def login(
            data: schemas.User.UserLogin,
            response: Response,
            db: AsyncSession = Depends(get_db),
        ):
            user = await models.User.User.authenticate(
                db=db, email=data.email, password=data.password
            )
        
            if not user:
                raise BadRequestException(detail="Email hoặc mật khẩu không chính xác")
        
            if not user.is_active:
                raise ForbiddenException(detail="Tài khoản chưa được kích hoạt")
        
            # Thay from_orm bằng model_validate
            user_schema = schemas.User.User.model_validate(user)
            token_pair = create_token_pair(user=user_schema)
            add_refresh_token_cookie(response=response, token=token_pair.refresh.token)
        
            return {"token": token_pair.access.token}
#     user.is_active = True
#     await user.save(db=db)
#     return {"msg": "Successfully activated"}


# @router.post("/logout", response_model=schemas.SuccessResponseScheme)
# async def logout(
#     token: Annotated[str, Depends(oauth2_scheme)],
#     db: AsyncSession = Depends(get_db),
# ):
#     payload = await decode_access_token(token=token, db=db)
#     black_listed = models.BlackListToken(
#         id=payload[JTI], expire=datetime.utcfromtimestamp(payload[EXP])
#     )
#     await black_listed.save(db=db)

#     return {"msg": "Succesfully logout"}


# @router.post("/forgot-password", response_model=schemas.SuccessResponseScheme)
# async def forgot_password(
#     data: schemas.ForgotPasswordSchema,
#     bg_task: BackgroundTasks,
#     db: AsyncSession = Depends(get_db),
# ):
#     user = await models.User.find_by_email(db=db, email=data.email)
#     if user:
#         user_schema = schemas.User.from_orm(user)
#         reset_token = mail_token(user_schema)

#         mail_task_data = schemas.MailTaskSchema(
#             user=user_schema,
#             body=schemas.MailBodySchema(type="password-reset", token=reset_token),
#         )
#         bg_task.add_task(user_mail_event, mail_task_data)

#     return {"msg": "Reset token sended successfully your email check your email"}


# @router.post("/password-reset", response_model=schemas.SuccessResponseScheme)
# async def password_reset_token(
#     token: str,
#     data: schemas.PasswordResetSchema,
#     db: AsyncSession = Depends(get_db),
# ):
#     payload = await decode_access_token(token=token, db=db)
#     user = await models.User.find_by_id(db=db, id=payload[SUB])
#     if not user:
#         raise NotFoundException(detail="User not found")

#     user.password = get_password_hash(data.password)
#     await user.save(db=db)

#     return {"msg": "Password succesfully updated"}


# @router.post("/password-update", response_model=schemas.SuccessResponseScheme)
# async def password_update(
#     token: Annotated[str, Depends(oauth2_scheme)],
#     data: schemas.PasswordUpdateSchema,
#     db: AsyncSession = Depends(get_db),
# ):
#     payload = await decode_access_token(token=token, db=db)
#     user = await models.User.find_by_id(db=db, id=payload[SUB])
#     if not user:
#         raise NotFoundException(detail="User not found")

#     # raise Validation error
#     if not verify_password(data.old_password, user.password):
#         try:
#             schemas.OldPasswordErrorSchema(old_password=False)
#         except ValidationError as e:
#             raise RequestValidationError(e.raw_errors)
#     user.password = get_password_hash(data.password)
#     await user.save(db=db)

#     return {"msg": "Successfully updated"}