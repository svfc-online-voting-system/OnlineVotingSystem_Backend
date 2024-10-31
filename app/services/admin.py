""" These are the services that the admin are able to access. """


class Admin:  # pylint: disable=R0903
    """ Class that will contain all the action the admin user can do. """
    @classmethod
    def approve_vote(cls, vote_metadata: dict):
        """ Service that will call and validate the approval of the vote """
        pass
