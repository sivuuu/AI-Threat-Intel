from django.urls import path, include
from rest_framework.routers import DefaultRouter
from threat_hunting.views import (
    DashboardStatsView, LogIngestionView, SecurityLogViewSet,
    AlertViewSet, IncidentViewSet, DetectionRuleViewSet,
    WatchlistViewSet, AuditLogViewSet, SeedSampleScenariosView
)

router = DefaultRouter()
router.register(r'logs', SecurityLogViewSet, basename='security-logs')
router.register(r'alerts', AlertViewSet, basename='alerts')
router.register(r'incidents', IncidentViewSet, basename='incidents')
router.register(r'rules', DetectionRuleViewSet, basename='rules')
router.register(r'watchlists', WatchlistViewSet, basename='watchlists')
router.register(r'audit', AuditLogViewSet, basename='audit')

urlpatterns = [
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('ingest/', LogIngestionView.as_view(), name='log-ingest'),
    path('seed-scenarios/', SeedSampleScenariosView.as_view(), name='seed-scenarios'),
    path('', include(router.urls)),
]
