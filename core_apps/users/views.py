import logging
from typing import Optional
from django.conf import settings
from djoser.social.views import ProviderAuthView
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

logger = logging.getLogger(__name__)


def set_auth_cookies(
    response: Response, access_token: str, refresh_token: Optional[str] = None
) -> None:
    """
    Sets authentication cookies for the access and refresh tokens.

    This function configures cookies for the access token and, if provided,
    the refresh token. It also sets a 'logged_in' cookie to indicate
    successful authentication.

    Args:
        response (Response): The response object to set the cookies on.
        access_token (str): The JWT access token to be set as a cookie.
        refresh_token (Optional[str]): The JWT refresh token to be set as a cookie.
    """
    access_token_lifetime = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds(
    )
    cookie_settings = {
        "path": settings.COOKIE_PATH,
        "secure": settings.COOKIE_SECURE,
        "httponly": settings.COOKIE_HTTPONLY,
        "samesite": settings.COOKIE_SAMESITE,
        "max_age": access_token_lifetime,  # eg. 1800 secs (30 minutes)
    }
    response.set_cookie("access", access_token, **cookie_settings)

    if refresh_token:
        refresh_token_lifetime = settings.SIMPLE_JWT[
            "REFRESH_TOKEN_LIFETIME"
        ].total_seconds()

        # refresh cookie settings has same settings as access cookie settings except max_age
        refresh_cookie_settings = cookie_settings.copy()

        # update max age for refresh cookie eg.from 30 mins to 1 day
        refresh_cookie_settings["max_age"] = refresh_token_lifetime
        response.set_cookie("refresh", refresh_token,
                            **refresh_cookie_settings)

    # logged in cookie will have the same lifespan as the access token
    logged_in_cookie_settings = cookie_settings.copy()
    logged_in_cookie_settings["httponly"] = False  # allow JS to read cookie
    response.set_cookie("logged_in", "true", **logged_in_cookie_settings)


class CustomTokenObtainPairView(TokenObtainPairView):

    def post(self, request: Request, *args, **kwargs) -> Response:
        """
        Authenticate user with credentials.
        Set cookies with obtained access and refresh tokens.
        Return response with success message
        """
        token_res = super().post(request, *args, **kwargs)

        if token_res.status_code == status.HTTP_200_OK:
            access_token = token_res.data.get("access")
            refresh_token = token_res.data.get("refresh")

            if access_token and refresh_token:
                set_auth_cookies(
                    token_res,
                    access_token=access_token,
                    refresh_token=refresh_token,
                )

                # remove access token from response
                token_res.data.pop("access", None)
                # remove refresh token from response
                token_res.data.pop("refresh", None)

                token_res.data["message"] = "Login Successful."
            else:
                token_res.data["message"] = "Login Failed"
                logger.error(
                    "Access or refresh token not found in login response data")

        return token_res


class CustomTokenRefreshView(TokenRefreshView):

    def post(self, request: Request, *args, **kwargs) -> Response:
        """
        Handles the refresh token request and sets new authentication cookies.

        """
        # get refresh token from cookies
        refresh_token = request.COOKIES.get("refresh")

        # add refresh token to request data
        if refresh_token:
            request.data["refresh"] = refresh_token

        # call the superclass method to refresh the tokens
        refresh_res = super().post(request, *args, **kwargs)

        #  If successful, it retrieves the new access and refresh tokens from the response data.
        if refresh_res.status_code == status.HTTP_200_OK:
            access_token = refresh_res.data.get("access")
            refresh_token = refresh_res.data.get("refresh")

            # If both tokens are present, it calls the set_auth_cookies function to set these tokens as cookies in the response.
            if access_token and refresh_token:
                set_auth_cookies(
                    refresh_res,
                    access_token=access_token,
                    refresh_token=refresh_token,
                )

                # remove access and refresh tokens from response
                refresh_res.data.pop("access", None)
                refresh_res.data.pop("refresh", None)

                refresh_res.data["message"] = "Access tokens refreshed successfully"
            else:
                refresh_res.data["message"] = (
                    "Access or refresh tokens not found in refresh response data"
                )
                logger.error(
                    "Access or refresh token not found in refresh response data"
                )

        return refresh_res


class CustomProviderAuthView(ProviderAuthView):

    def post(self, request: Request, *args, **kwargs) -> Response:
        """
        Authenticate user with credentials.
        Set cookies with obtained access and refresh tokens.
        Return response with success message
        """
        provider_res = super().post(request, *args, **kwargs)

        if provider_res.status_code == status.HTTP_201_CREATED:
            access_token = provider_res.data.get("access")
            refresh_token = provider_res.data.get("refresh")

            if access_token and refresh_token:
                set_auth_cookies(
                    provider_res,
                    access_token=access_token,
                    refresh_token=refresh_token,
                )

                provider_res.data.pop("access", None)
                provider_res.data.pop("refresh", None)

                provider_res.data["message"] = "You are logged in Successful."
            else:
                provider_res.data["message"] = (
                    "Access or refresh token not found in provider response"
                )
                logger.error(
                    "Access or refresh token not found in provider response data"
                )

        return provider_res


class LogoutAPIView(APIView):

    def post(self, request: Request, *args, **kwargs):
        """
        Handles user logout by deleting authentication cookies.

        This method clears the 'access', 'refresh', and 'logged_in' cookies
        from the response, indicating that the user has successfully logged out.

        Args:
            request (Request): The request object for the logout action.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Response: An empty response with a 204 No Content status indicating successful logout.
        """
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        response.delete_cookie("logged_in")
        return response
