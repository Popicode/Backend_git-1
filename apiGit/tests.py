from datetime import timedelta

import pyotp
from django.core import mail
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from . import services
from .models import Category, Loan, ResourceItem, ResourceTitle, Sanction, Student, User


class LoanFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.admin = User.objects.create_user(
            username='admin', email='admin@inacap.cl', password='clave12345', role='ADMIN'
        )
        services.generate_mfa_secret(self.admin)
        self.operator = User.objects.create_user(
            username='operador', email='op@inacap.cl', password='clave12345'
        )
        services.generate_mfa_secret(self.operator)
        self.student = Student.objects.create(
            rut='12345678-5', institutional_email='alumno@inacapmail.cl',
            first_name='Ana', last_name='Pérez',
        )
        tablets = Category.objects.create(name='Tablet', term_unit='HOURS')
        title = ResourceTitle.objects.create(category=tablets, title='Tablet Samsung')
        self.item = ResourceItem.objects.create(resource_title=title, barcode='TAB-001')

        self.client = APIClient()
        self.client.force_authenticate(user=self.operator)

    def create_loan(self, term_value=3):
        return self.client.post('/api/loans/', {
            'resource_item': self.item.id, 'student': self.student.id, 'term_value': term_value,
        }, format='json')

    def test_login_returns_token(self):
        client = APIClient()
        response = client.post('/api/auth/login/', {
            'username': 'operador', 'password': 'clave12345',
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('mfa_challenge', response.data)

        code = pyotp.TOTP(self.operator.mfa_secret).now()
        response = client.post('/api/auth/mfa/verify/', {
            'mfa_challenge': response.data['mfa_challenge'], 'code': code,
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_wrong_mfa_code_is_rejected(self):
        client = APIClient()
        response = client.post('/api/auth/login/', {
            'username': 'operador', 'password': 'clave12345',
        }, format='json')
        totp = pyotp.TOTP(self.operator.mfa_secret)
        valid_codes = {
            totp.at(timezone.now() + timedelta(seconds=offset))
            for offset in (-30, 0, 30)
        }
        wrong_code = next(f'{number:06d}' for number in range(10)
                          if f'{number:06d}' not in valid_codes)
        response = client.post('/api/auth/mfa/verify/', {
            'mfa_challenge': response.data['mfa_challenge'], 'code': wrong_code,
        }, format='json')
        self.assertEqual(response.status_code, 401)

    def test_login_without_mfa_configured_requires_enrollment(self):
        User.objects.create_user(
            username='sinmfa', email='sinmfa@inacap.cl', password='clave12345'
        )
        client = APIClient()
        response = client.post('/api/auth/login/', {
            'username': 'sinmfa', 'password': 'clave12345',
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['mfa_setup_required'])
        self.assertIn('mfa_challenge', response.data)
        self.assertNotIn('access', response.data)
        self.assertNotIn('refresh', response.data)

    def test_endpoints_need_login(self):
        response = APIClient().get('/api/loans/')
        self.assertEqual(response.status_code, 401)

    def test_create_loan(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.create_loan()
        self.assertEqual(response.status_code, 201)
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, 'ON_LOAN')
        self.assertEqual(response.data['checked_out_by'], self.operator.id)
        # the receipt email was sent
        self.assertEqual(len(mail.outbox), 1)
        loan = Loan.objects.get(pk=response.data['id'])
        self.assertEqual(loan.receipt.delivery_status, 'SENT')

    def test_invalid_hours_term(self):
        response = self.create_loan(term_value=2)
        self.assertEqual(response.status_code, 400)

    def test_item_already_lent_returns_409(self):
        self.create_loan()
        response = self.create_loan()
        self.assertEqual(response.status_code, 409)

    def test_return_on_time_no_sanction(self):
        loan_id = self.create_loan().data['id']
        response = self.client.post(f'/api/loans/{loan_id}/return/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'RETURNED')
        self.assertFalse(Sanction.objects.exists())

        # returning twice gives an error
        response = self.client.post(f'/api/loans/{loan_id}/return/')
        self.assertEqual(response.status_code, 400)

    def test_late_return_creates_sanction_and_blocks_student(self):
        loan_id = self.create_loan().data['id']
        # we move the due date to the past to simulate a delay of 90 minutes
        Loan.objects.filter(pk=loan_id).update(
            due_at=timezone.now() - timedelta(minutes=90)
        )
        self.client.post(f'/api/loans/{loan_id}/return/')

        sanction = Sanction.objects.get(loan_id=loan_id)
        self.assertGreaterEqual(sanction.minutes_late, 90)
        self.assertEqual((sanction.ends_at - sanction.starts_at).days, 2)

        response = self.client.get(f'/api/students/{self.student.id}/eligibility/')
        self.assertFalse(response.data['can_borrow'])
        self.assertEqual(self.create_loan().status_code, 400)

    def test_operator_cannot_see_users(self):
        response = self.client.get('/api/users/')
        self.assertEqual(response.status_code, 403)

    def test_admin_creates_user_with_hashed_password_and_soft_delete(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.post('/api/users/', {
            'username': 'nuevo', 'email': 'nuevo@inacap.cl', 'password': 'otraclave123',
        }, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertNotIn('password', response.data)
        self.assertNotIn('mfa_secret', response.data)
        self.assertNotIn('mfa_provisioning_uri', response.data)
        self.assertFalse(response.data['mfa_confirmed'])
        user = User.objects.get(username='nuevo')
        self.assertTrue(user.check_password('otraclave123'))
        self.assertFalse(user.mfa_confirmed)

        response = self.client.delete(f'/api/users/{user.id}/')
        self.assertEqual(response.status_code, 204)
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    def test_staff_email_must_be_inacap(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.post('/api/users/', {
            'username': 'malo', 'email': 'malo@gmail.com', 'password': 'otraclave123',
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_student_rut_is_validated(self):
        response = self.client.post('/api/students/', {
            'rut': '12345678-9', 'institutional_email': 'otro@inacapmail.cl',
            'first_name': 'Juan', 'last_name': 'Soto',
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('rut', response.data)

    def test_catalog_availability_and_barcode(self):
        response = self.client.get('/api/resource-titles/availability/')
        self.assertEqual(response.data[0]['available_items'], 1)
        response = self.client.get('/api/resource-items/by-barcode/TAB-001/')
        self.assertEqual(response.status_code, 200)

    def test_category_delete_is_soft(self):
        category = Category.objects.create(name='Audífonos', term_unit='HOURS')
        response = self.client.delete(f'/api/categories/{category.id}/')
        self.assertEqual(response.status_code, 204)
        category.refresh_from_db()
        self.assertFalse(category.is_active)

    def test_resource_title_delete_is_soft(self):
        other_title = ResourceTitle.objects.create(
            category=Category.objects.get(name='Tablet'), title='Tablet Lenovo'
        )
        response = self.client.delete(f'/api/resource-titles/{other_title.id}/')
        self.assertEqual(response.status_code, 204)
        other_title.refresh_from_db()
        self.assertFalse(other_title.is_active)

    def test_temporary_account_requires_valid_until_on_update(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.patch(
            f'/api/users/{self.operator.id}/', {'is_temporary': True}, format='json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('valid_until', response.data)
