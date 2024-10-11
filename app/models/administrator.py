""" File for the Administrator accounts model """
from sqlalchemy import Column, Integer, ForeignKey, delete
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from app.models.base import Base
from app.utils.engine import get_session


class Administrator(Base):
    __tablename__ = 'administrators'
    admin_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.user_id'), nullable=False)
    user = relationship('User', back_populates='Administrator', uselist=True, cascade='all, delete-orphan')
    
    @classmethod
    def add_admin(cls, user_id: int) -> int:
        """ Responsible for adding a new admin """
        session = get_session()
        try:
            new_admin = cls(
                user_id=user_id
            )
            session.add(new_admin)
            session.commit()
            return new_admin.admin_id
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()
    
    @classmethod
    def delete_admin(cls, admin_id: int) -> bool:
        """ Responsible for deleting an admin """
        session = get_session()
        try:
            delete_statement = (
                delete(cls)
                .where(cls.admin_id == admin_id)
                .returning()
            )
            result = session.execute(delete_statement).first()
            session.commit()
            if result is None:
                return False
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()
