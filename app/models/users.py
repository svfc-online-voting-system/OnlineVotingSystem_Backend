"""
	Description:
		This module contains the User class which is a SQLAlchemy model for the
		users table in the database.

	Extended Description:
		The User class contains the following columns:
				- user_id: Integer, primary key, autoincrement
				- username: String, unique, not null
				- salt: String, not null
				- hashed_password: String, not null
				- email: String, not null
				- date_of_birth: Date, not null
				- account_creation_date: Date, not null
				- first_name: String, not null
				- last_name: String, not null

		The User class also contains the following class methods:
				- create_user: Creates a new user in the database.
				- get_user_by_email: Retrieves a user from the database by email.
				- check_credentials: Checks the credentials of a user.

		The User class also creates the users table in the database.

    Returns:
            user: User
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Date, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError
import bcrypt
from app.utils.engine import get_session, get_engine
from app.exception.password_error import PasswordError
from app.exception.email_not_found_error import EmailNotFound

Base = declarative_base()


class User(Base):
    """Class representing a User in the database."""
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(45), unique=True, nullable=False)
    salt = Column(String(45), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    account_creation_date = Column(Date, nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)

    @classmethod
    def create_user(cls, user_data_dict):
        """ Creates a new user in the database. """
        account_creation_date = datetime.now()
        session = get_session()
        first_name, last_name, email, plaintext_password, date_of_birth = (
            user_data_dict.get('first_name'),
            user_data_dict.get('last_name'),
            user_data_dict.get('email'),
            user_data_dict.get('password'),
            user_data_dict.get('date_of_birth')
        )

        try:
            salt = bcrypt.gensalt(rounds=16).decode('utf=8')
            hashed_password = bcrypt.hashpw(plaintext_password.encode(
                'utf-8'), salt.encode('utf-8')).decode('utf-8')

            new_user = cls(
                username=email.split("@")[0],
                salt=salt,
                hashed_password=hashed_password,
                email=email,
                date_of_birth=date_of_birth,
                account_creation_date=account_creation_date,
                first_name=first_name,
                last_name=last_name
            )

            session.add(new_user)
            session.commit()
            return new_user
        except IntegrityError as int_err:
            session.rollback()
            raise int_err
        except Exception as e:
            session.rollback()
            raise e

    @classmethod
    def get_user_by_email(cls, email):
        """Retrieves a user from the database by email."""
        session = get_session()
        return session.query(cls).filter_by(email=email).first()

    @classmethod
    def check_credentials(cls, email, plaintext_password):
        """Checks the credentials of a user."""
        session = get_session()

        hashed_password_row = session.execute(
            select(User.hashed_password).filter_by(email=email)).first()

        if hashed_password_row is None:
            raise EmailNotFound

        hashed_password_from_db = hashed_password_row[0]

        if bcrypt.checkpw(
            plaintext_password.encode('utf-8'),
            hashed_password_from_db.encode('utf-8')
        ):
            return session.execute(select(User.user_id)
                                   .filter_by(email=email)).first()
        raise PasswordError


Base.metadata.create_all(bind=get_engine())
