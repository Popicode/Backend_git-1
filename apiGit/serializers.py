from rest_framework import serializers

from .models import (
    AuditLog, Category, Loan, LoanReceipt, ResourceItem, ResourceTitle, Sanction, Student, User,
)
from .validations import validate_rut, validate_staff_email, validate_student_email


class LoginSerializer(serializers.Serializer):
    """Validate credentials without trimming the password."""

    username = serializers.CharField(max_length=150)
    password = serializers.CharField(trim_whitespace=False, write_only=True)


class MfaChallengeSerializer(serializers.Serializer):
    """A short-lived credential limited to one MFA operation."""

    mfa_challenge = serializers.CharField(max_length=2048)


class MfaCodeSerializer(MfaChallengeSerializer):
    """Require six ASCII digits, preserving leading zeros."""

    code = serializers.RegexField(r'\A[0-9]{6}\Z', trim_whitespace=False)

    def validate_code(self, value: str) -> str:
        if not isinstance(self.initial_data.get('code'), str):
            raise serializers.ValidationError('The code must be a six-digit string.')
        return value


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'role',
            'is_temporary',
            'valid_from',
            'valid_until',
            'is_active',
            'mfa_confirmed',
            'password',
        ]
        # password is never returned in the response
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
            'is_active': {'read_only': True},
            'mfa_confirmed': {'read_only': True},
        }

    def validate_email(self, value):
        return validate_staff_email(value)

    def validate(self, attrs):
        # when creating a user the password is required
        if self.instance is None and not attrs.get('password'):
            raise serializers.ValidationError({'password': 'La contraseña es obligatoria'})

        valid_from = attrs.get('valid_from')
        valid_until = attrs.get('valid_until')
        if valid_from and valid_until and valid_until <= valid_from:
            raise serializers.ValidationError(
                {'valid_until': 'La fecha de caducidad debe ser posterior al inicio'}
            )

        # RF-03: a temporary account always needs an expiry date, on create and on update
        is_temporary = attrs.get('is_temporary', getattr(self.instance, 'is_temporary', False))
        effective_valid_until = attrs.get(
            'valid_until', getattr(self.instance, 'valid_until', None)
        )
        if is_temporary and not effective_valid_until:
            raise serializers.ValidationError(
                {'valid_until': 'Una cuenta temporal necesita fecha de caducidad'}
            )
        return attrs

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        updated_fields = list(validated_data)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        if password:
            instance.set_password(password)
            updated_fields.append('password')
        # Never overwrite a concurrently consumed MFA challenge from a stale instance.
        instance.save(update_fields=updated_fields)
        return instance


class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = [
            'id',
            'rut',
            'institutional_email',
            'first_name',
            'last_name',
            'is_active',
            'created_at',
        ]
        read_only_fields = ['is_active', 'created_at']

    def validate_rut(self, value):
        return validate_rut(value)

    def validate_institutional_email(self, value):
        return validate_student_email(value)


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'term_unit', 'is_active']


class ResourceTitleSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)

    class Meta:
        model = ResourceTitle
        fields = [
            'id',
            'category',
            'category_name',
            'title',
            'author_or_brand',
            'reference_code',
            'is_active',
        ]


class CatalogSerializer(serializers.ModelSerializer):
    """Title with its stock, used in the counter view (RF-05)."""
    category_name = serializers.CharField(source='category.name', read_only=True)
    total_items = serializers.IntegerField(read_only=True)
    available_items = serializers.IntegerField(read_only=True)

    class Meta:
        model = ResourceTitle
        fields = [
            'id',
            'title',
            'author_or_brand',
            'category',
            'category_name',
            'total_items',
            'available_items',
        ]


class ResourceItemSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='resource_title.title', read_only=True)

    class Meta:
        model = ResourceItem
        fields = [
            'id',
            'resource_title',
            'title',
            'barcode',
            'status',
            'location',
            'acquired_at',
        ]

    def validate_status(self, value):
        # ON_LOAN is only set by the loan service, not by hand
        if value == ResourceItem.Status.ON_LOAN:
            raise serializers.ValidationError(
                'El estado ON_LOAN se asigna solo al registrar un préstamo'
            )
        if self.instance and self.instance.status == ResourceItem.Status.ON_LOAN:
            raise serializers.ValidationError(
                'No se puede cambiar el estado de un ejemplar que está prestado'
            )
        return value


class LoanReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoanReceipt
        fields = ['id', 'recipient_email', 'sent_at', 'delivery_status']


class LoanSerializer(serializers.ModelSerializer):
    """Used to show loans (read only). To create a loan use LoanCreateSerializer."""
    resource_item_title = serializers.CharField(
        source='resource_item.resource_title.title', read_only=True
    )
    barcode = serializers.CharField(source='resource_item.barcode', read_only=True)
    student_name = serializers.SerializerMethodField()

    class Meta:
        model = Loan
        fields = [
            'id',
            'resource_item',
            'barcode',
            'resource_item_title',
            'student',
            'student_name',
            'checked_out_by',
            'checked_in_by',
            'started_at',
            'term_value',
            'term_unit',
            'due_at',
            'returned_at',
            'status',
        ]
        read_only_fields = fields

    def get_student_name(self, obj):
        return f'{obj.student.first_name} {obj.student.last_name}'


class LoanCreateSerializer(serializers.Serializer):
    """Input data to register a loan. due_at, term_unit and operator are calculated."""
    resource_item = serializers.PrimaryKeyRelatedField(queryset=ResourceItem.objects.all())
    student = serializers.PrimaryKeyRelatedField(queryset=Student.objects.all())
    term_value = serializers.IntegerField(min_value=1)


class SanctionSerializer(serializers.ModelSerializer):
    student_rut = serializers.CharField(source='student.rut', read_only=True)

    class Meta:
        model = Sanction
        fields = [
            'id',
            'student',
            'student_rut',
            'loan',
            'minutes_late',
            'starts_at',
            'ends_at',
            'rule_applied',
            'is_active',
        ]


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'user',
            'username',
            'action',
            'entity_name',
            'entity_id',
            'ip_address',
            'created_at',
        ]
