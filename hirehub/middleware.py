class CSRFFromCookieMiddleware:
    """
    Reads the 'csrftoken' cookie and injects it into request.META['HTTP_X_CSRFTOKEN']
    so Django can validate CSRF without the frontend manually setting headers.
    """
    def __init__(self, get_response):
        self.get_response = get_response    

    def __call__(self, request):
        if "HTTP_X_CSRFTOKEN" not in request.META:
            token = request.COOKIES.get("csrftoken")
            if token:
                request.META["HTTP_X_CSRFTOKEN"] = token
        return self.get_response(request)
