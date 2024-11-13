""" Wraps the profile related services. """

from app.models.user import ProfileOperations


class ProfileService:  # pylint: disable=too-few-public-methods
    """Wraps the profile related services."""

    @classmethod
    def get_my_profile_settings(
        cls, user_id: int
    ):  # pylint: disable=missing-function-docstring
        return ProfileInfoService.get_my_profile_settings(user_id)


class ProfileInfoService:  # pylint: disable=too-few-public-methods
    """Wraps the profile related services."""

    @classmethod
    def get_my_profile_settings(
        cls, user_id: int
    ):  # pylint: disable=missing-function-docstring
        if not isinstance(user_id, int):
            raise ValueError("User ID must be an integer.")

        return ProfileOperations.get_my_profile_settings(user_id)

    @classmethod
    def update_profile(cls):  # pylint: disable=missing-function-docstring
        pass
