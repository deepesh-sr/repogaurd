"""T2 DRF router fixture."""
from rest_framework.permissions import IsAuthenticated
from rest_framework.routers import DefaultRouter
from rest_framework.viewsets import ModelViewSet

from .views import DashboardView  # noqa: F401  (import shape realism)


class NoteViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]


router = DefaultRouter()
router.register(r"notes", NoteViewSet, basename="note")

urlpatterns = router.urls
