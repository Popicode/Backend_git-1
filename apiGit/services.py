import binascii
import math
import secrets
from datetime import timedelta

import pyotp
from django.conf import settings
from django.core import signing
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from rest_framework import serializers, status
from rest_framework.exceptions import APIException

from .models import AuditLog, Loan, LoanReceipt, ResourceItem, Sanction, Student, User
from .selectors import student_can_borrow
from .validations import validate_term


class ItemNotAvailable(APIException):
    """Returns 409 Conflict when the item is already lent or can't be lent."""
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'El ejemplar no está disponible.'
    default_code = 'item_not_available'


# ---------- audit log ----------

def record_audit_event(user: User, action: str, entity_name: str, entity_id: int,
                       ip_address: str = None) -> AuditLog:
    """RNF-05: saves who did what and from which IP."""
    return AuditLog.objects.create(
        user=user,
        action=action,
        entity_name=entity_name,
        entity_id=entity_id,
        ip_address=ip_address,
    )


# ---------- users ----------

def create_staff_user(data: dict, created_by: User = None, ip_address: str = None) -> User:
    """RF-02 / RF-03: creates an admin or operator. Password is hashed by create_user()."""
    password = data.pop('password', None)
    if data.get('is_temporary') and not data.get('valid_until'):
        raise serializers.ValidationError(
            {'valid_until': 'Una cuenta temporal necesita fecha de caducidad'}
        )
    user = User.objects.create_user(password=password, **data)
    if created_by:
        record_audit_event(created_by, 'USER_CREATED', 'User', user.id, ip_address)
    return user


def deactivate_user(user: User, done_by: User, ip_address: str = None) -> User:
    """RF-02: soft delete, we never delete users from the database."""
    user.is_active = False
    user.save(update_fields=['is_active'])
    record_audit_event(done_by, 'USER_DEACTIVATED', 'User', user.id, ip_address)
    return user


def expire_temporary_accounts() -> int:
    """RN-02: turns off temporary accounts whose valid_until already passed."""
    now = timezone.now()
    return User.objects.filter(
        is_temporary=True, is_active=True, valid_until__lt=now
    ).update(is_active=False)


# ---------- MFA (RF-01) ----------

MFA_CHALLENGE_SALT = 'apiGit.mfa-challenge'
MFA_CHALLENGE_MAX_AGE = 300  # 5 minutos para completar el segundo factor
MFA_MAX_FAILED_ATTEMPTS = 5


def generate_mfa_secret(user: User) -> str:
    """Legacy helper: provision an already-confirmed secret (not for signup)."""
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    user.mfa_confirmed = True
    user.mfa_pending_secret = ''
    user.mfa_challenge_nonce = ''
    user.mfa_failed_attempts = 0
    user.save(update_fields=[
        'mfa_secret', 'mfa_confirmed', 'mfa_pending_secret',
        'mfa_challenge_nonce', 'mfa_failed_attempts',
    ])
    return secret


def build_mfa_provisioning_uri(user: User, secret: str | None = None) -> str:
    """Build an authenticator URI for an explicitly supplied or active secret."""
    return pyotp.TOTP(user.mfa_secret if secret is None else secret).provisioning_uri(
        name=user.email, issuer_name='Biblioteca INACAP'
    )


def _invalid_mfa_challenge() -> serializers.ValidationError:
    return serializers.ValidationError({
        'mfa_challenge': 'Invalid or expired challenge. Sign in again.',
    })


def _validate_mfa_account(user: User) -> None:
    now = timezone.now()
    if not user.is_active or (user.is_temporary and (
        not user.valid_until or user.valid_until <= now
        or (user.valid_from and user.valid_from > now)
    )):
        raise _invalid_mfa_challenge()


def _mfa_password_binding(user: User) -> str:
    # Signed tokens are readable: never include the stored password hash itself.
    return salted_hmac(MFA_CHALLENGE_SALT, user.password).hexdigest()


@transaction.atomic
def create_mfa_challenge(user: User) -> str:
    """Issue a password-bound, five-minute challenge and invalidate prior logins."""
    try:
        current = User.objects.select_for_update().get(pk=user.pk)
    except User.DoesNotExist:
        raise _invalid_mfa_challenge() from None
    _validate_mfa_account(current)
    if not constant_time_compare(user.password, current.password):
        raise _invalid_mfa_challenge()
    current.mfa_challenge_nonce = secrets.token_hex(32)
    current.mfa_failed_attempts = 0
    current.mfa_pending_secret = ''
    current.save(update_fields=[
        'mfa_challenge_nonce', 'mfa_failed_attempts', 'mfa_pending_secret',
    ])
    challenge = signing.dumps({
        'user_id': current.pk,
        'nonce': current.mfa_challenge_nonce,
        'password_binding': _mfa_password_binding(current),
        'purpose': 'verify' if current.mfa_confirmed else 'setup',
    }, salt=MFA_CHALLENGE_SALT)
    # The login response must describe the same enrollment state as this token.
    user.mfa_confirmed = current.mfa_confirmed
    return challenge


def resolve_mfa_challenge(challenge: str) -> User:
    """Validate a challenge without consuming it; authentication needs verification."""
    with transaction.atomic():
        return _resolve_mfa_challenge(challenge)


def _resolve_mfa_challenge(challenge: str, purpose: str | None = None) -> User:
    """Resolve and lock the current challenge inside the caller's transaction."""
    if not isinstance(challenge, str) or not challenge:
        raise _invalid_mfa_challenge()
    try:
        data = signing.loads(
            challenge, salt=MFA_CHALLENGE_SALT, max_age=MFA_CHALLENGE_MAX_AGE
        )
    except (signing.BadSignature, ValueError, TypeError):
        raise _invalid_mfa_challenge() from None
    if not isinstance(data, dict) or type(data.get('user_id')) is not int:
        raise _invalid_mfa_challenge()
    if not all(isinstance(data.get(key), str) for key in (
        'nonce', 'password_binding', 'purpose',
    )):
        raise _invalid_mfa_challenge()
    try:
        user = User.objects.select_for_update().get(pk=data['user_id'])
    except (User.DoesNotExist, ValueError, OverflowError):
        raise _invalid_mfa_challenge() from None
    _validate_mfa_account(user)
    expected_purpose = 'verify' if user.mfa_confirmed else 'setup'
    if (
        data['purpose'] != expected_purpose
        or (purpose is not None and data['purpose'] != purpose)
        or not user.mfa_challenge_nonce
        or not constant_time_compare(data['nonce'], user.mfa_challenge_nonce)
        or not constant_time_compare(data['password_binding'], _mfa_password_binding(user))
        or user.mfa_failed_attempts >= MFA_MAX_FAILED_ATTEMPTS
    ):
        raise _invalid_mfa_challenge()
    return user


@transaction.atomic
def start_mfa_enrollment(challenge: str) -> dict[str, str]:
    """Return the same pending secret for repeated calls with a valid setup token."""
    user = _resolve_mfa_challenge(challenge, 'setup')
    if not user.mfa_pending_secret:
        user.mfa_pending_secret = pyotp.random_base32()
        user.save(update_fields=['mfa_pending_secret'])
    return {
        'mfa_secret': user.mfa_pending_secret,
        'mfa_provisioning_uri': build_mfa_provisioning_uri(user, user.mfa_pending_secret),
    }


def _verify_totp(secret: str, code: str) -> bool:
    if not secret or not isinstance(code, str) or len(code) != 6:
        return False
    if not code.isascii() or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def _complete_mfa_challenge(challenge: str, code: str, purpose: str) -> User | None:
    """Consume success or record failure while holding the user's row lock.

    Call from autocommit: an enclosing transaction can roll back attempt updates
    if a deferred verifier error propagates through it.
    """
    error: ValueError | OverflowError | OSError | None = None
    result: User | None = None
    with transaction.atomic():
        user = _resolve_mfa_challenge(challenge, purpose)
        secret = user.mfa_pending_secret if purpose == 'setup' else user.mfa_secret
        if not secret:
            raise _invalid_mfa_challenge()
        # Base32 decoding can fail; PyOTP's local-time conversion can also fail.
        # Defer these errors until after saving the attempt, without swallowing
        # programming errors or database failures. binascii.Error is a ValueError.
        try:
            valid = _verify_totp(secret, code)
        except (binascii.Error, ValueError, OverflowError, OSError) as exc:
            valid = False
            error = exc
        if valid:
            if purpose == 'setup':
                user.mfa_secret = secret
                user.mfa_confirmed = True
            user.mfa_pending_secret = ''
            user.mfa_challenge_nonce = ''
            user.mfa_failed_attempts = 0
            user.save(update_fields=[
                'mfa_secret', 'mfa_confirmed', 'mfa_pending_secret',
                'mfa_challenge_nonce', 'mfa_failed_attempts',
            ])
            result = user
        else:
            user.mfa_failed_attempts += 1
            if user.mfa_failed_attempts >= MFA_MAX_FAILED_ATTEMPTS:
                user.mfa_challenge_nonce = ''
                user.mfa_pending_secret = ''
            user.save(update_fields=[
                'mfa_failed_attempts', 'mfa_challenge_nonce', 'mfa_pending_secret',
            ])
    if error is not None:
        raise error
    return result


def confirm_mfa_enrollment(challenge: str, code: str) -> User | None:
    """Activate the pending secret on a correct TOTP and consume the setup token."""
    return _complete_mfa_challenge(challenge, code, 'setup')


def verify_mfa_challenge(challenge: str, code: str) -> User | None:
    """Verify an enrolled user's TOTP and consume the login token exactly once."""
    return _complete_mfa_challenge(challenge, code, 'verify')


def verify_mfa_code(user: User, code: str) -> bool:
    """RF-01: checks the 6-digit TOTP code, tolerating one 30s window of drift."""
    return user.mfa_confirmed and _verify_totp(user.mfa_secret, code)


# ---------- students ----------

def deactivate_student(student: Student, done_by: User, ip_address: str = None) -> Student:
    student.is_active = False
    student.save(update_fields=['is_active'])
    record_audit_event(done_by, 'STUDENT_DEACTIVATED', 'Student', student.id, ip_address)
    return student


# ---------- loans ----------

def calculate_due_at(start, term_value: int, term_unit: str):
    if term_unit == 'HOURS':
        return start + timedelta(hours=term_value)
    return start + timedelta(days=term_value)


@transaction.atomic
def create_loan(resource_item: ResourceItem, student: Student, operator: User,
                term_value: int, ip_address: str = None) -> Loan:
    """RF-06: registers a loan, marks the item as ON_LOAN and sends the receipt."""
    # lock the row so two operators can't lend the same item at the same time
    item = ResourceItem.objects.select_for_update().select_related(
        'resource_title__category'
    ).get(pk=resource_item.pk)

    if item.status != ResourceItem.Status.AVAILABLE:
        raise ItemNotAvailable()

    can_borrow, reason = student_can_borrow(student)
    if not can_borrow:
        raise serializers.ValidationError({'student': reason})

    # the term unit comes from the category (hours for equipment, days for books)
    term_unit = item.resource_title.category.term_unit
    validate_term(term_value, term_unit)

    now = timezone.now()
    loan = Loan.objects.create(
        resource_item=item,
        student=student,
        checked_out_by=operator,
        term_value=term_value,
        term_unit=term_unit,
        due_at=calculate_due_at(now, term_value, term_unit),
    )

    item.status = ResourceItem.Status.ON_LOAN
    item.save(update_fields=['status'])

    record_audit_event(operator, 'LOAN_CREATED', 'Loan', loan.id, ip_address)

    # the email is sent only if the transaction is saved correctly
    transaction.on_commit(lambda: send_loan_receipt(loan))
    return loan


def send_loan_receipt(loan: Loan) -> LoanReceipt:
    """RF-07: sends the receipt to the student's email and saves the timestamp."""
    item_title = loan.resource_item.resource_title.title
    message = (
        f'Hola {loan.student.first_name},\n\n'
        f'Registramos tu préstamo de: {item_title} ({loan.resource_item.barcode}).\n'
        f'Inicio: {timezone.localtime(loan.started_at):%d-%m-%Y %H:%M}\n'
        f'Debes devolverlo antes de: {timezone.localtime(loan.due_at):%d-%m-%Y %H:%M}\n\n'
        f'Biblioteca INACAP'
    )
    try:
        send_mail(
            subject='Comprobante de préstamo',
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[loan.student.institutional_email],
        )
        delivery_status = 'SENT'
    except Exception:
        delivery_status = 'FAILED'

    # if it was already sent before (resend), we update the same receipt
    receipt, _created = LoanReceipt.objects.update_or_create(
        loan=loan,
        defaults={
            'recipient_email': loan.student.institutional_email,
            'delivery_status': delivery_status,
            'sent_at': timezone.now(),
        },
    )
    return receipt


@transaction.atomic
def return_loan(loan: Loan, operator: User, ip_address: str = None) -> Loan:
    """RF-08: registers the return. If it is late, a sanction is created (RF-09)."""
    loan = Loan.objects.select_for_update().get(pk=loan.pk)

    if loan.status == Loan.Status.RETURNED:
        raise serializers.ValidationError({'detail': 'Este préstamo ya fue devuelto.'})

    now = timezone.now()
    loan.returned_at = now
    loan.checked_in_by = operator
    loan.status = Loan.Status.RETURNED
    loan.save(update_fields=['returned_at', 'checked_in_by', 'status'])

    item = loan.resource_item
    item.status = ResourceItem.Status.AVAILABLE
    item.save(update_fields=['status'])

    record_audit_event(operator, 'ITEM_RETURNED', 'Loan', loan.id, ip_address)

    if now > loan.due_at:
        apply_late_return_sanction(loan)

    return loan


# rule: 1 day of block for each hour (or part of an hour) of delay
SANCTION_RULE = '1_DAY_PER_HOUR_LATE'


def apply_late_return_sanction(loan: Loan) -> Sanction:
    """RF-09: calculates the end of the block depending on the minutes late."""
    minutes_late = int((loan.returned_at - loan.due_at).total_seconds() // 60)
    minutes_late = max(minutes_late, 1)
    days_blocked = math.ceil(minutes_late / 60)

    return Sanction.objects.create(
        student=loan.student,
        loan=loan,
        minutes_late=minutes_late,
        starts_at=loan.returned_at,
        ends_at=loan.returned_at + timedelta(days=days_blocked),
        rule_applied=SANCTION_RULE,
    )


def mark_overdue_loans() -> int:
    """Changes ACTIVE loans that passed their due date to OVERDUE."""
    now = timezone.now()
    return Loan.objects.filter(status=Loan.Status.ACTIVE, due_at__lt=now).update(
        status=Loan.Status.OVERDUE
    )


def finish_expired_sanctions() -> int:
    """Sanctions whose ends_at already passed are no longer active."""
    now = timezone.now()
    return Sanction.objects.filter(is_active=True, ends_at__lte=now).update(is_active=False)
