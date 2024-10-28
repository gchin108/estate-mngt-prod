import logging
from typing import Optional, Tuple
from django.conf import settings
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication, AuthUser
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import Token

logger = logging.getLogger(__name__)


class CookieAuthentication(JWTAuthentication):
    # Method to authenticate a user based on the request
    def authenticate(self, request: Request) -> Optional[Tuple[AuthUser, Token]]:
        """
        Authenticates a user based on the provided request.

        This method attempts to extract a JWT from the authorization header 
        or from the cookies. If a valid token is found, it validates the token 
        and retrieves the associated user.

        Parameters:
            request (Request): The HTTP request object containing the 
                            headers and cookies.

        Returns:
            Optional[Tuple[AuthUser, Token]]:
                - A tuple containing the authenticated user (AuthUser) 
                and the validated token (Token) if authentication is 
                successful.
                - None if authentication fails due to the absence of a valid 
                token or a validation error.
        """
        # Retrieve the authorization header from the request
        header = self.get_header(request)
        raw_token = None  # Initialize raw_token to None

        # Check if the authorization header is present
        if header is not None:
            # Extract the raw token from the header
            raw_token = self.get_raw_token(header)
        # If no header, check for the token in the cookies
        elif settings.COOKIE_NAME in request.COOKIES:
            # Retrieve the raw token from cookies using a predefined cookie name
            raw_token = request.COOKIES.get(settings.COOKIE_NAME)

        # If a raw token is found, proceed to validate it
        if raw_token is not None:
            try:
                # Validate the token and retrieve user information
                validated_token = self.get_validated_token(raw_token)
                # Return the authenticated user and the validated token
                return self.get_user(validated_token), validated_token

            except TokenError as e:
                # Log an error if token validation fails
                logger.error(f"Token validation error: {str(e)}")
        # Return None if authentication fails
        return None
