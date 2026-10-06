from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from .views import (
    AuditLogViewSet, CategoryViewSet, LoanViewSet, ResourceItemViewSet, ResourceTitleViewSet,
    SanctionViewSet, StudentViewSet, UserViewSet, inventory_report_view, login_view,
    logout_view, mfa_verify_view, mfa_setup_view, mfa_confirm_view, shift_summary_view,
)

app_name = 'apiGit'

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'students', StudentViewSet, basename='student')
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'resource-titles', ResourceTitleViewSet, basename='resource-title')
router.register(r'resource-items', ResourceItemViewSet, basename='resource-item')
router.register(r'loans', LoanViewSet, basename='loan')
router.register(r'sanctions', SanctionViewSet, basename='sanction')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')

urlpatterns = [
    path('auth/login/', login_view, name='login'),
    path('auth/mfa/verify/', mfa_verify_view, name='mfa-verify'),
    path('auth/mfa/setup/', mfa_setup_view, name='mfa-setup'),
    path('auth/mfa/confirm/', mfa_confirm_view, name='mfa-confirm'),
    path('auth/logout/', logout_view, name='logout'),
    path('reports/inventory/', inventory_report_view, name='inventory-report'),
    path('reports/shift-summary/', shift_summary_view, name='shift-summary'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh')
]

urlpatterns += router.urls
