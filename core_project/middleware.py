import uuid

from django.conf import settings


class RequestIDMiddleware:
    """Attach a request ID to logs and every HTTP response."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get(settings.REQUEST_ID_HEADER) or str(uuid.uuid4())
        request.request_id = request_id
        response = self.get_response(request)
        response[settings.REQUEST_ID_HEADER] = request_id
        return response
