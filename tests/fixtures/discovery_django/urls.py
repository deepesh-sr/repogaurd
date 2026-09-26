"""T2 Django fixture: FBV open, CBV protected, AllowAny view, include(), router."""
from django.urls import include, path

from . import views

urlpatterns = [
    path("", views.home, name="home"),  # bare FBV -> allowany-default (global AllowAny)
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),  # IsAuthenticated
    path("public/", views.PublicView.as_view(), name="public"),  # explicit AllowAny -> open
    path("api/", include("api_urls")),
]
