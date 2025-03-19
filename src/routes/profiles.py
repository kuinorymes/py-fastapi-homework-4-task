from uuid import uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    status,
    HTTPException,
    Form,
    UploadFile,
    Request
)

from fastapi.params import Depends, Header, File
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_s3_storage_client, get_jwt_auth_manager
from exceptions import (
    TokenExpiredError,
    InvalidTokenError,
    S3ConnectionError,
    S3BucketNotFoundError,
    S3FileUploadError
)
from schemas.profiles import ProfileResponseSchema, ProfileCreateRequestSchema
from database import get_db, UserModel, UserProfileModel, UserGroupEnum
from security.http import get_token
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface

router = APIRouter()


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def create_user_profile(
        user_id: int,
        request: Request,
        profile_data: ProfileCreateRequestSchema = Depends(ProfileCreateRequestSchema.from_form),
        db: AsyncSession = Depends(get_db),
        token: str = Depends(get_token),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        s3_client: S3StorageInterface = Depends(get_s3_storage_client),
) -> ProfileResponseSchema:
    try:
        payload = jwt_manager.decode_access_token(token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token."
        )

    current_user_id = payload.get("user_id")
    if not current_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )

    if current_user_id != user_id:
        stmt = (
            select(UserModel)
            .where(UserModel.id == current_user_id)
            .options(joinedload(UserModel.group))
        )
        result = await db.execute(stmt)
        user_group = result.scalars().first()
        if not user_group or not user_group.has_group(UserGroupEnum.ADMIN):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to edit this profile."
            )

    stmt = select(UserModel).filter_by(id=user_id, is_active=True)
    result = await db.execute(stmt)
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active."
        )

    stmt = select(UserProfileModel).filter_by(user_id=user_id)
    result = await db.execute(stmt)
    existing_profile = result.scalars().first()
    if existing_profile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile."
        )

    avatar_key = None
    avatar_url = None
    if profile_data.avatar:
        avatar_key = (
            f"avatars/{user_id}_avatar.{profile_data.avatar.filename.split('.')[-1]}"
        )
        try:
            file_data = await profile_data.avatar.read()
            await s3_client.upload_file(file_name=avatar_key, file_data=file_data)
            avatar_url = await s3_client.get_file_url(file_name=avatar_key)
        except (
                S3ConnectionError,
                S3BucketNotFoundError,
                S3FileUploadError
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to upload avatar. Please try again later.",
            )

    try:
        new_profile = UserProfileModel(
            user_id=user_id,
            first_name=profile_data.first_name,
            last_name=profile_data.last_name,
            gender=profile_data.gender,
            date_of_birth=profile_data.date_of_birth,
            info=profile_data.info,
            avatar=avatar_key if avatar_key else None,
        )
        db.add(new_profile)
        await db.commit()
        await db.refresh(new_profile)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create profile due to database error.",
        ) from e

    response_data = ProfileResponseSchema(
        id=new_profile.id,
        user_id=new_profile.user_id,
        first_name=new_profile.first_name,
        last_name=new_profile.last_name,
        gender=new_profile.gender,
        date_of_birth=new_profile.date_of_birth,
        info=new_profile.info,
        avatar=avatar_url if avatar_key else None,
    )
    return response_data
