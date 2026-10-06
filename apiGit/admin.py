from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm
from .models import Sanction, Student, ResourceTitle, ResourceItem, LoanReceipt, Category, Loan, AuditLog, User

# Register your models here.

admin.site.register([Sanction, Student, ResourceItem, ResourceTitle, Loan, LoanReceipt, Category, AuditLog])


class StaffPasswordChangeForm(AdminPasswordChangeForm):
    """Keep MFA state intact when changing a password from a stale admin form."""

    def save(self, commit: bool = True) -> User:
        user = super().save(commit=False)
        if commit:
            user.save(update_fields=['password'])
        return user


@admin.register(User)
class StaffUserAdmin(UserAdmin):
    """Manage accounts without revealing or editing authenticator secrets."""

    fieldsets = UserAdmin.fieldsets + (
        ('Library account', {
            'fields': ('role', 'is_temporary', 'valid_from', 'valid_until', 'mfa_confirmed'),
        }),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Library account', {'fields': ('email', 'role')}),
    )
    readonly_fields = ('mfa_confirmed',)
    change_password_form = StaffPasswordChangeForm

    def save_model(self, request, obj: User, form, change: bool) -> None:
        if change:
            # MFA services own these fields, including while this form is open.
            obj.save(update_fields=[
                field.name for field in obj._meta.concrete_fields
                if not field.primary_key and not field.name.startswith('mfa_')
            ])
        else:
            super().save_model(request, obj, form, change)
