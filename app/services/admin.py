""" These are the services that the admin are able to access. """

from app.models.votes import Votes
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError

from app.exception.votes_exception import VoteDoesNotExists


class Admin:  # pylint: disable=R0903
    """ Class that will contain all the action the admin user can do. """
    @classmethod
    def approve_vote(cls, vote_metadata: dict):
        """ Service that will call and validate the approval of the vote """
        try:
            if (vote_metadata.get('vote_id') is None or
                vote_metadata.get('user_id') is None or
                not str(vote_metadata.get('vote_id')).isnumeric() or
                not str(vote_metadata.get('vote_id')).isnumeric()):
                raise ValueError
            votes = Votes()
            result = votes.approve_vote(vote_metadata=vote_metadata)
            if result:
                return result
            raise ValueError
        except ValueError as ve:
            raise ve
        except VoteDoesNotExists as vdne:
            raise vdne
        except (IntegrityError, DataError, OperationalError, DatabaseError) as e:
            raise e
