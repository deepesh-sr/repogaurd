"""T2 Django fixture views."""
from django.views import View
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView


def home(request):
    return None


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return None


class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return None


class UnusedView(View):
    pass
