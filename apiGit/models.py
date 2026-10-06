from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

class User(AbstractUser):

    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Administrator"
        OPERATOR = "OPERATOR", "Desk operator"

    email = models.EmailField(unique=True)                      # must end in @inacap
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.OPERATOR)
    is_temporary = models.BooleanField(default=False)           # RF-03
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)   # auto-expiry
    mfa_secret = models.CharField(max_length=64, blank=True)    # TOTP
    mfa_confirmed = models.BooleanField(default=False)
    mfa_pending_secret = models.CharField(max_length=64, blank=True, default='')
    mfa_challenge_nonce = models.CharField(max_length=64, blank=True, default='')
    mfa_failed_attempts = models.PositiveSmallIntegerField(default=0)
    # is_active (heredado) = soft delete. NUNCA borrado físico.
    def __str__(self):
        return f"{self.username} ({self.get_full_name()})"

    
class Student(models.Model):
    rut = models.CharField(max_length=12, unique=True)
    institutional_email = models.EmailField(unique=True)        # @inacap | @inacapmail
    first_name = models.CharField(max_length=80)
    last_name = models.CharField(max_length=80)
    is_active = models.BooleanField(default=True)               # soft delete
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.rut} - {self.first_name} {self.last_name}"

    
class Category(models.Model):
    class TermUnit(models.TextChoices):
        HOURS = "HOURS", "Hours"
        DAYS = "DAYS", "Days"

    name = models.CharField(max_length=60, unique=True)         # Libro, Tablet, Audífono...
    term_unit = models.CharField(max_length=5, choices=TermUnit.choices)
    is_active = models.BooleanField(default=True)
    def __str__(self):
        return self.name

class ResourceTitle(models.Model):
    category = models.ForeignKey(Category, on_delete=models.PROTECT, related_name="titles")
    title = models.CharField(max_length=200)
    author_or_brand = models.CharField(max_length=120, blank=True)
    reference_code = models.CharField(max_length=60, blank=True)   # ISBN / SKU
    is_active = models.BooleanField(default=True)
    def __str__(self):
        return f"{self.title} ({self.category.name})"

    
class ResourceItem(models.Model):
    class Status(models.TextChoices):
        AVAILABLE = "AVAILABLE", "Available"
        ON_LOAN = "ON_LOAN", "On loan"
        MAINTENANCE = "MAINTENANCE", "In maintenance"
        RETIRED = "RETIRED", "Retired"
    def __str__(self):
        return f"{self.barcode} ({self.resource_title.title})"
    resource_title = models.ForeignKey(
        ResourceTitle, on_delete=models.PROTECT, related_name="items"
    )
    barcode = models.CharField(max_length=60, unique=True)      # serie / código de barras
    status = models.CharField(
        max_length=12, choices=Status.choices, default=Status.AVAILABLE
    )
    location = models.CharField(max_length=60, blank=True)
    acquired_at = models.DateField(null=True, blank=True)

class Loan(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        RETURNED = "RETURNED", "Returned"
        OVERDUE = "OVERDUE", "Overdue"

    resource_item = models.ForeignKey(
        ResourceItem, on_delete=models.PROTECT, related_name="loans"
    )
    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name="loans")
    checked_out_by = models.ForeignKey(                         # operador que entrega
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="loans_given"
    )
    checked_in_by = models.ForeignKey(                          # operador que recibe
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="loans_received",
        null=True,
        blank=True,
    )
    started_at = models.DateTimeField(auto_now_add=True)
    term_value = models.PositiveSmallIntegerField()             # 1 | 3 | 6 | N días
    term_unit = models.CharField(max_length=5, choices=Category.TermUnit.choices)
    due_at = models.DateTimeField()                             # calculado en services.py
    returned_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)

    def __str__(self):
        return f"Loan of {self.resource_item.barcode} to {self.student.rut} ({self.status})"
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["resource_item"],
                condition=models.Q(status="ACTIVE"),
                name="unique_active_loan_per_item",
            )
        ]

class LoanReceipt(models.Model):
    loan = models.OneToOneField(Loan, on_delete=models.PROTECT, related_name="receipt")
    recipient_email = models.EmailField()
    sent_at = models.DateTimeField(auto_now_add=True)           # marca auditable
    delivery_status = models.CharField(max_length=8, default="SENT")
    def __str__(self):
        return f"Receipt for loan {self.loan.id} to {self.recipient_email}"


class Sanction(models.Model):
    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name="sanctions")
    loan = models.OneToOneField(Loan, on_delete=models.PROTECT, related_name="sanction")
    minutes_late = models.PositiveIntegerField()
    starts_at = models.DateTimeField()
    ends_at = models.DateTimeField()                            # fin del bloqueo
    rule_applied = models.CharField(max_length=60)
    is_active = models.BooleanField(default=True)
    def __str__(self):
        return f"Sanction for {self.student.rut} ({self.rule_applied})"

    
class AuditLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="audit_logs"
    )
    action = models.CharField(max_length=40)          # LOAN_CREATED, ITEM_RETURNED...
    entity_name = models.CharField(max_length=40)
    entity_id = models.PositiveIntegerField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"AuditLog: {self.action} on {self.entity_name} ({self.entity_id}) by {self.user.username}"
