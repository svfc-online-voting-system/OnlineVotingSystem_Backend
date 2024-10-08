"""
    This module contains the user profile model.
"""
import os

from sqlalchemy import ForeignKey, Column, Integer, String, Date
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy import select, insert

from app.models.base import Base
from app.utils.engine import get_session

class UserProfile(Base):
    """
    This class is responsible for the user profile model.
    """
    __tablename__ = 'profile_table'
    user_id = Column(Integer, ForeignKey('users.user_id'), primary_key=True)
    username = Column(String(45), unique=True, nullable=False)
    email = Column(String(100), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    account_creation_date = Column(Date, nullable=False)
    user = relationship("User", back_populates="profile")
    FRONT_END_VERIFY_EMAIL_URL = os.getenv('LOCAL_FRONTEND_URL') + '/auth/verify-email/'
    @classmethod
    def add_new_profile_data(cls, profile_data: dict):
        """Add new profile data to the database."""
        session = get_session()
        # pylint: disable=R0801
        try:
            user_id = profile_data.get('user_id')
            username = profile_data.get('username')
            email = profile_data.get('email')
            first_name = profile_data.get('first_name')
            last_name = profile_data.get('last_name')
            date_of_birth = profile_data.get('date_of_birth')
            account_creation_date = profile_data.get('account_creation_date')
            query = (
                insert(cls).values(
                    user_id=user_id,
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    date_of_birth=date_of_birth,
                    account_creation_date=account_creation_date
                )
            )
            session.execute(query)
            session.commit()
            return 'success'
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()
    @classmethod
    def email_exists(cls, email: str) -> bool:
        """Check if an email exists in the database."""
        session = get_session()
        try:
            email = str(email)
            stmt = select(cls.email).where(email == cls.email)
            result = session.execute(stmt).first()
            if result:
                return True
            return False  # pylint: disable=R0801
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()
