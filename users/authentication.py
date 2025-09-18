from rest_framework.authentication import TokenAuthentication

class CookieTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get("access_token")        
        if token is None:
            return None        
        return self.authenticate_credentials(token)
