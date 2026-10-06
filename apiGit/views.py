from datetime import timedelta

import qrcode
import qrcode.image.svg
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.cache import never_cache
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import (
    action, api_view, authentication_classes, permission_classes, throttle_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from . import selectors, services
from .models import AuditLog, Category, Loan, ResourceItem, ResourceTitle, Sanction, Student, User
from .permissions import IsAdminRole
from .serializers import (
    AuditLogSerializer, CatalogSerializer, CategorySerializer, LoanCreateSerializer,
    LoanReceiptSerializer, LoanSerializer, ResourceItemSerializer, ResourceTitleSerializer,
    SanctionSerializer, StudentSerializer, UserSerializer,
    LoginSerializer, MfaChallengeSerializer, MfaCodeSerializer,
)


def get_client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


# ---------- auth ----------

class AuthRateThrottle(ScopedRateThrottle):
    """Limit password and MFA requests from each client address."""

    def allow_request(self, request: Request, view: APIView) -> bool:
        view.throttle_scope = 'auth'
        return super().allow_request(request, view)


def jwt_session_response(user: User, request: Request) -> Response:
    """Issue a session only after a successful second factor."""
    refresh = RefreshToken.for_user(user)
    services.record_audit_event(user, 'LOGIN', 'User', user.id, get_client_ip(request))
    return Response({
        'refresh': str(refresh), 'access': str(refresh.access_token),
        'user': UserSerializer(user).data,
    })


@never_cache
@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([AuthRateThrottle])
def login_view(request: Request) -> Response:
    """RF-01, step 1: checks username/password and returns a challenge for the MFA code."""
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data['username']
    password = serializer.validated_data['password']

    user = authenticate(username=username, password=password)
    if user is None:
        return Response({'detail': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

    now = timezone.now()
    if user.is_temporary:
        if (not user.valid_until or user.valid_until <= now) or \
                (user.valid_from and user.valid_from > now):
            return Response(
                {'detail': 'Tu cuenta temporal no está vigente'},
                status=status.HTTP_403_FORBIDDEN,
            )

    challenge = services.create_mfa_challenge(user)
    return Response({
        'mfa_challenge': challenge, 'mfa_setup_required': not user.mfa_confirmed,
    })


@never_cache
@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([AuthRateThrottle])
def mfa_verify_view(request: Request) -> Response:
    """RF-01, step 2: checks the TOTP code and issues the real JWT."""
    serializer = MfaCodeSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = services.verify_mfa_challenge(
        serializer.validated_data['mfa_challenge'], serializer.validated_data['code'],
    )
    if user is None:
        return Response({'detail': 'Código MFA inválido'}, status=status.HTTP_401_UNAUTHORIZED)

    return jwt_session_response(user, request)


@never_cache
@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([AuthRateThrottle])
def mfa_setup_view(request: Request) -> Response:
    """Show enrollment material only to the password-verified account owner."""
    serializer = MfaChallengeSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = services.start_mfa_enrollment(serializer.validated_data['mfa_challenge'])
    qr = qrcode.make(data['mfa_provisioning_uri'], image_factory=qrcode.image.svg.SvgPathImage)
    data['qr_code_svg'] = qr.to_string(encoding='unicode')
    return Response(data)


@never_cache
@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([AuthRateThrottle])
def mfa_confirm_view(request: Request) -> Response:
    """Activate MFA and issue the first session after proof of enrollment."""
    serializer = MfaCodeSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = services.confirm_mfa_enrollment(
        serializer.validated_data['mfa_challenge'], serializer.validated_data['code'],
    )
    if user is None:
        return Response({'detail': 'Invalid MFA code.'}, status=status.HTTP_401_UNAUTHORIZED)
    return jwt_session_response(user, request)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    refresh_str = request.data.get('refresh')
    if not refresh_str:
        return Response({'detail': 'Debes enviar el refresh token'}, status=status.HTTP_400_BAD_REQUEST)
    try:    
        RefreshToken(refresh_str).blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)
    except TokenError:
        return Response(
                {'detail': 'Refresh token inválido'},
                status = status.HTTP_400_BAD_REQUEST)

# ---------- users (only admins) ----------

class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAdminRole]

    def get_queryset(self):
        users = User.objects.all().order_by('id')
        role = self.request.query_params.get('role')
        is_active = self.request.query_params.get('is_active')
        is_temporary = self.request.query_params.get('is_temporary')
        if role:
            users = users.filter(role=role)
        if is_active is not None:
            users = users.filter(is_active=is_active.lower() == 'true')
        if is_temporary is not None:
            users = users.filter(is_temporary=is_temporary.lower() == 'true')
        return users

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = services.create_staff_user(
            dict(serializer.validated_data),
            created_by=request.user,
            ip_address=get_client_ip(request),
        )
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        # soft delete: we only deactivate the user
        user = self.get_object()
        services.deactivate_user(user, request.user, get_client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------- students ----------

class StudentViewSet(viewsets.ModelViewSet):
    serializer_class = StudentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        students = Student.objects.all().order_by('last_name')
        search = self.request.query_params.get('search')
        if search:
            students = students.filter(rut__icontains=search) | \
                students.filter(institutional_email__icontains=search)
        return students

    def destroy(self, request, *args, **kwargs):
        student = self.get_object()
        services.deactivate_student(student, request.user, get_client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['get'])
    def eligibility(self, request, pk=None):
        """RN-03: tells the operator if the student can borrow before lending."""
        student = self.get_object()
        can_borrow, reason = selectors.student_can_borrow(student)
        return Response({'can_borrow': can_borrow, 'reason': reason})

    @action(detail=True, methods=['get'])
    def loans(self, request, pk=None):
        student = self.get_object()
        loans = selectors.list_student_loan_history(student)
        return Response(LoanSerializer(loans, many=True).data)


# ---------- catalog / inventory ----------

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all().order_by('name')
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        # soft delete: titles/items may reference this category
        category = self.get_object()
        category.is_active = False
        category.save(update_fields=['is_active'])
        return Response(status=status.HTTP_204_NO_CONTENT)


class ResourceTitleViewSet(viewsets.ModelViewSet):
    serializer_class = ResourceTitleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        titles = ResourceTitle.objects.select_related('category').order_by('title')
        category = self.request.query_params.get('category')
        search = self.request.query_params.get('search')
        if category:
            titles = titles.filter(category_id=category)
        if search:
            titles = titles.filter(title__icontains=search)
        return titles

    @action(detail=False, methods=['get'])
    def availability(self, request):
        """Counter view: total and available stock per title (RF-05)."""
        titles = selectors.list_catalog_with_availability(
            category_id=request.query_params.get('category'),
            search=request.query_params.get('search'),
        )
        return Response(CatalogSerializer(titles, many=True).data)

    def destroy(self, request, *args, **kwargs):
        # soft delete: items may still reference this title
        title = self.get_object()
        title.is_active = False
        title.save(update_fields=['is_active'])
        return Response(status=status.HTTP_204_NO_CONTENT)


class ResourceItemViewSet(viewsets.ModelViewSet):
    serializer_class = ResourceItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        items = ResourceItem.objects.select_related('resource_title').order_by('id')
        item_status = self.request.query_params.get('status')
        resource_title = self.request.query_params.get('resource_title')
        if item_status:
            items = items.filter(status=item_status)
        if resource_title:
            items = items.filter(resource_title_id=resource_title)
        return items

    def destroy(self, request, *args, **kwargs):
        # we don't delete items, they are marked as RETIRED
        item = self.get_object()
        if item.status == ResourceItem.Status.ON_LOAN:
            return Response(
                {'detail': 'No se puede dar de baja un ejemplar prestado'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        item.status = ResourceItem.Status.RETIRED
        item.save(update_fields=['status'])
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'], url_path=r'by-barcode/(?P<barcode>[^/]+)')
    def by_barcode(self, request, barcode=None):
        """Quick search when the operator scans the barcode."""
        try:
            item = selectors.get_item_by_barcode(barcode)
        except ResourceItem.DoesNotExist:
            return Response({'detail': 'Ejemplar no encontrado'}, status=status.HTTP_404_NOT_FOUND)
        return Response(ResourceItemSerializer(item).data)


# ---------- loans ----------

class LoanViewSet(mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.CreateModelMixin,
                  viewsets.GenericViewSet):
    """Loans can't be edited or deleted, only created and returned."""
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return selectors.list_loans(
            status=self.request.query_params.get('status'),
            operator_id=self.request.query_params.get('operator'),
            student_id=self.request.query_params.get('student'),
        )

    def get_serializer_class(self):
        if self.action == 'create':
            return LoanCreateSerializer
        return LoanSerializer

    def create(self, request, *args, **kwargs):
        serializer = LoanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        loan = services.create_loan(
            resource_item=data['resource_item'],
            student=data['student'],
            operator=request.user,
            term_value=data['term_value'],
            ip_address=get_client_ip(request),
        )
        return Response(LoanSerializer(loan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'], url_path='return')
    def return_loan(self, request, pk=None):
        loan = self.get_object()
        loan = services.return_loan(loan, request.user, get_client_ip(request))
        return Response(LoanSerializer(loan).data)

    @action(detail=True, methods=['post'], url_path='resend-receipt')
    def resend_receipt(self, request, pk=None):
        loan = self.get_object()
        receipt = services.send_loan_receipt(loan)
        return Response(LoanReceiptSerializer(receipt).data, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['get'])
    def overdue(self, request):
        loans = selectors.list_overdue_loans()
        return Response(LoanSerializer(loans, many=True).data)


# ---------- sanctions and audit (read only) ----------

class SanctionViewSet(viewsets.ReadOnlyModelViewSet):
    """Sanctions are created automatically when a loan is returned late."""
    serializer_class = SanctionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        sanctions = Sanction.objects.select_related('student').order_by('-starts_at')
        student = self.request.query_params.get('student')
        is_active = self.request.query_params.get('is_active')
        if student:
            sanctions = sanctions.filter(student_id=student)
        if is_active is not None:
            sanctions = sanctions.filter(is_active=is_active.lower() == 'true')
        return sanctions


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """The audit log can't be modified (RNF-05)."""
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminRole]

    def get_queryset(self):
        logs = AuditLog.objects.select_related('user').order_by('-created_at')
        user = self.request.query_params.get('user')
        date_from = self.request.query_params.get('date_from')
        if user:
            logs = logs.filter(user_id=user)
        if date_from:
            date = parse_datetime(date_from)
            if date:
                logs = logs.filter(created_at__gte=date)
        return logs


# ---------- reports ----------

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def inventory_report_view(request):
    return Response(list(selectors.inventory_report()))


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def shift_summary_view(request):
    # by default the shift is the last 8 hours
    since = timezone.now() - timedelta(hours=8)
    return Response(selectors.shift_summary(request.user, since))
