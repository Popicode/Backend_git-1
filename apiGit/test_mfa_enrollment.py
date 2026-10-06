"""Integration coverage for password-gated MFA enrollment and authentication."""

import time
from datetime import timedelta
from unittest.mock import patch
from xml.etree import ElementTree

import pyotp
from django.conf import settings
from django.contrib import admin
from django.core.cache import cache
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.test import APITestCase

from . import services
from .models import User
from .serializers import UserSerializer


@override_settings(PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'])
class MFAEnrollmentTests(APITestCase):
    """Exercise real API requests without bypassing password or TOTP validation."""

    password = 'Test-only-password-429!'
    login_url = '/api/auth/login/'
    setup_url = '/api/auth/mfa/setup/'
    confirm_url = '/api/auth/mfa/confirm/'
    verify_url = '/api/auth/mfa/verify/'

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(
            username='enrollment', email='enrollment@inacap.cl', password=self.password,
        )

    def login(self, confirmed: bool = False) -> str:
        response = self.client.post(self.login_url, {
            'username': self.user.username, 'password': self.password,
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['mfa_setup_required'], not confirmed)
        self.assertEqual(set(response.data), {'mfa_setup_required', 'mfa_challenge'})
        return response.data['mfa_challenge']

    def setup_mfa(self, challenge: str) -> Response:
        response = self.client.post(self.setup_url, {
            'mfa_challenge': challenge,
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        return response

    def submit_code(self, endpoint: str, challenge: str, code: object) -> Response:
        return self.client.post(endpoint, {
            'mfa_challenge': challenge, 'code': code,
        }, format='json')

    def assert_rejected(self, response: Response) -> None:
        # The contract permits validation/authentication errors, never success or 500.
        self.assertIn(response.status_code, (400, 401, 403, 429), response.data)
        for field in ('access', 'refresh', 'mfa_secret', 'mfa_provisioning_uri', 'qr_code_svg'):
            self.assertNotIn(field, response.data)

    def assert_tokens(self, response: Response) -> None:
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data['access'])
        self.assertTrue(response.data['refresh'])
        self.assertTrue(response.data['user']['mfa_confirmed'])
        self.assertNotIn('mfa_secret', response.data['user'])
        self.assertNotIn('mfa_provisioning_uri', response.data['user'])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}")
        self.assertEqual(self.client.get('/api/categories/').status_code, 200)
        self.client.credentials()

    def test_first_login_setup_and_confirmation_issue_usable_tokens(self) -> None:
        challenge = self.login()
        self.assertEqual(self.client.get('/api/categories/').status_code, 401)
        setup = self.setup_mfa(challenge)
        self.assertIn('no-store', setup['Cache-Control'])
        self.assertNotIn('access', setup.data)
        self.assertNotIn('refresh', setup.data)
        secret = setup.data['mfa_secret']
        repeated = self.setup_mfa(challenge)
        self.assertEqual(repeated.data['mfa_secret'], secret)
        self.assertEqual(pyotp.parse_uri(setup.data['mfa_provisioning_uri']).secret, secret)
        svg = ElementTree.fromstring(setup.data['qr_code_svg'])
        self.assertEqual(svg.tag, '{http://www.w3.org/2000/svg}svg')
        self.assertTrue(list(svg))
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_confirmed)
        response = self.submit_code(self.confirm_url, challenge, pyotp.TOTP(secret).now())
        self.assert_tokens(response)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_confirmed)
        self.assertEqual(self.user.mfa_secret, secret)
        refresh = self.client.post('/api/api/token/refresh/', {
            'refresh': response.data['refresh'],
        }, format='json')
        self.assertEqual(refresh.status_code, 200)
        self.assertIn('access', refresh.data)

    def test_legacy_helper_marks_user_confirmed_and_login_verifies(self) -> None:
        secret = services.generate_mfa_secret(self.user)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_confirmed)
        challenge = self.login(confirmed=True)
        self.assert_tokens(self.submit_code(self.verify_url, challenge, pyotp.TOTP(secret).now()))

    def test_setup_challenge_cannot_verify(self) -> None:
        challenge = self.login()
        secret = self.setup_mfa(challenge).data['mfa_secret']
        self.assert_rejected(self.submit_code(self.verify_url, challenge, pyotp.TOTP(secret).now()))
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_confirmed)

    def test_verify_challenge_cannot_setup_or_confirm(self) -> None:
        secret = services.generate_mfa_secret(self.user)
        challenge = self.login(confirmed=True)
        self.assert_rejected(self.client.post(self.setup_url, {
            'mfa_challenge': challenge,
        }, format='json'))
        self.assert_rejected(self.submit_code(self.confirm_url, challenge, pyotp.TOTP(secret).now()))
        self.user.refresh_from_db()
        self.assertEqual(self.user.mfa_secret, secret)

    def test_confirmation_requires_setup_first(self) -> None:
        self.assert_rejected(self.submit_code(self.confirm_url, self.login(), '123456'))
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_confirmed)

    def test_success_consumes_challenge_in_both_flows(self) -> None:
        challenge = self.login()
        secret = self.setup_mfa(challenge).data['mfa_secret']
        code = pyotp.TOTP(secret).now()
        self.assert_tokens(self.submit_code(self.confirm_url, challenge, code))
        self.assert_rejected(self.submit_code(self.confirm_url, challenge, code))
        self.assert_rejected(self.client.post(self.setup_url, {
            'mfa_challenge': challenge,
        }, format='json'))
        challenge = self.login(confirmed=True)
        self.assert_tokens(self.submit_code(self.verify_url, challenge, code))
        self.assert_rejected(self.submit_code(self.verify_url, challenge, code))

    def test_new_login_invalidates_previous_challenge_in_both_flows(self) -> None:
        for confirmed in (False, True):
            with self.subTest(confirmed=confirmed):
                if confirmed:
                    services.generate_mfa_secret(self.user)
                previous = self.login(confirmed)
                current = self.login(confirmed)
                self.assertNotEqual(previous, current)
                endpoint = self.verify_url if confirmed else self.setup_url
                response = self.client.post(endpoint, {
                    'mfa_challenge': previous, 'code': '123456',
                }, format='json')
                self.assert_rejected(response)

    def test_codes_must_be_exactly_six_ascii_digits_as_a_string(self) -> None:
        malformed = (123456, True, None, '', '12345', '1234567', 'abcdef',
                     '１２３４５６', '١٢٣٤٥٦', ' 123456', '123456 ', '123456\n', [], {})
        for confirmed in (False, True):
            if confirmed:
                services.generate_mfa_secret(self.user)
            challenge = self.login(confirmed)
            if not confirmed:
                self.setup_mfa(challenge)
            endpoint = self.verify_url if confirmed else self.confirm_url
            for code in malformed:
                with self.subTest(confirmed=confirmed, code=code):
                    # Isolate shape validation from request-rate throttling.
                    cache.clear()
                    response = self.submit_code(endpoint, challenge, code)
                    self.assertEqual(response.status_code, 400, response.data)
                    self.assertNotIn('access', response.data)

    def test_five_wrong_codes_exhaust_challenge_even_with_correct_sixth_code(self) -> None:
        for confirmed in (False, True):
            with self.subTest(confirmed=confirmed):
                cache.clear()
                if confirmed:
                    secret = services.generate_mfa_secret(self.user)
                challenge = self.login(confirmed)
                if not confirmed:
                    secret = self.setup_mfa(challenge).data['mfa_secret']
                endpoint = self.verify_url if confirmed else self.confirm_url
                totp = pyotp.TOTP(secret)
                # Avoid the one-in-a-million false failure of a hard-coded wrong code.
                valid_codes = {totp.at(timezone.now() + timedelta(seconds=offset))
                               for offset in (-30, 0, 30)}
                wrong = next(f'{number:06d}' for number in range(10)
                             if f'{number:06d}' not in valid_codes)
                for _ in range(5):
                    self.assert_rejected(self.submit_code(endpoint, challenge, wrong))
                cache.clear()  # The challenge limit must survive an IP throttle reset.
                self.assert_rejected(self.submit_code(endpoint, challenge, totp.now()))

    def test_challenges_expire_after_300_seconds(self) -> None:
        for confirmed in (False, True):
            with self.subTest(confirmed=confirmed):
                cache.clear()
                if confirmed:
                    secret = services.generate_mfa_secret(self.user)
                challenge = self.login(confirmed)
                if not confirmed:
                    secret = self.setup_mfa(challenge).data['mfa_secret']
                future = time.time() + 301
                with patch('django.core.signing.time.time', return_value=future):
                    endpoint = self.verify_url if confirmed else self.confirm_url
                    self.assert_rejected(self.submit_code(endpoint, challenge, pyotp.TOTP(secret).now()))
                    if not confirmed:
                        self.assert_rejected(self.client.post(self.setup_url, {
                            'mfa_challenge': challenge,
                        }, format='json'))

    def test_password_change_or_deactivation_invalidates_pending_challenge(self) -> None:
        for confirmed in (False, True):
            for change in ('password', 'is_active'):
                with self.subTest(confirmed=confirmed, change=change):
                    cache.clear()
                    self.user.set_password(self.password)
                    self.user.is_active = True
                    self.user.save()
                    if confirmed:
                        services.generate_mfa_secret(self.user)
                    challenge = self.login(confirmed)
                    if not confirmed:
                        self.setup_mfa(challenge)
                    self.user.refresh_from_db()
                    if change == 'password':
                        self.user.set_password('Changed-test-password-738!')
                    else:
                        self.user.is_active = False
                    self.user.save()
                    endpoint = self.verify_url if confirmed else self.confirm_url
                    self.assert_rejected(self.submit_code(
                        endpoint, challenge,
                        pyotp.TOTP(self.user.mfa_secret or self.user.mfa_pending_secret).now(),
                    ))
                    if not confirmed:
                        self.assert_rejected(self.client.post(self.setup_url, {
                            'mfa_challenge': challenge,
                        }, format='json'))

    def test_temporary_account_validity_is_rechecked_after_password(self) -> None:
        for confirmed in (False, True):
            for field, delta in (('valid_from', 1), ('valid_until', -1)):
                with self.subTest(confirmed=confirmed, field=field):
                    cache.clear()
                    self.user.is_temporary = True
                    self.user.valid_from = timezone.now() - timedelta(days=1)
                    self.user.valid_until = timezone.now() + timedelta(days=1)
                    self.user.save()
                    if confirmed:
                        services.generate_mfa_secret(self.user)
                    challenge = self.login(confirmed)
                    if not confirmed:
                        self.setup_mfa(challenge)
                    self.user.refresh_from_db()
                    setattr(self.user, field, timezone.now() + timedelta(days=delta))
                    self.user.save(update_fields=[field])
                    endpoint = self.verify_url if confirmed else self.confirm_url
                    self.assert_rejected(self.submit_code(
                        endpoint, challenge,
                        pyotp.TOTP(self.user.mfa_secret or self.user.mfa_pending_secret).now(),
                    ))

    def test_wrong_password_and_inactive_user_receive_no_challenge(self) -> None:
        for inactive in (False, True):
            with self.subTest(inactive=inactive):
                self.user.is_active = not inactive
                self.user.save(update_fields=['is_active'])
                response = self.client.post(self.login_url, {
                    'username': self.user.username,
                    'password': self.password if inactive else 'wrong-password',
                }, format='json')
                self.assertEqual(response.status_code, 401)
                self.assertNotIn('mfa_challenge', response.data)
                self.assertNotIn('access', response.data)

    def test_temporary_accounts_outside_validity_cannot_start_login(self) -> None:
        for field, delta in (('valid_from', 1), ('valid_until', -1)):
            with self.subTest(field=field):
                self.user.is_temporary = True
                self.user.valid_from = timezone.now() - timedelta(days=1)
                self.user.valid_until = timezone.now() + timedelta(days=1)
                setattr(self.user, field, timezone.now() + timedelta(days=delta))
                self.user.save()
                response = self.client.post(self.login_url, {
                    'username': self.user.username, 'password': self.password,
                }, format='json')
                self.assert_rejected(response)
                self.assertNotIn('mfa_challenge', response.data)

    def test_missing_or_tampered_challenges_never_expose_secrets(self) -> None:
        challenge = self.login()
        for endpoint in (self.setup_url, self.confirm_url, self.verify_url):
            for token in ('', 'invalid', challenge + 'tampered'):
                with self.subTest(endpoint=endpoint, token=token):
                    self.assert_rejected(self.submit_code(endpoint, token, '123456'))

    def test_admin_user_crud_never_discloses_secrets_or_accepts_confirmation(self) -> None:
        admin = User.objects.create_user(
            username='admin-mfa', email='admin-mfa@inacap.cl',
            password=self.password, role='ADMIN',
        )
        self.client.force_authenticate(admin)
        response = self.client.post('/api/users/', {
            'username': 'created', 'email': 'created@inacap.cl',
            'password': self.password, 'mfa_confirmed': True,
        }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        created = User.objects.get(username='created')
        self.assertFalse(created.mfa_confirmed)
        self.assertFalse(response.data['mfa_confirmed'])
        services.generate_mfa_secret(created)
        detail = self.client.get(f'/api/users/{created.pk}/')
        listing = self.client.get('/api/users/')
        for result in (response, detail, listing):
            self.assertNotContains(result, 'mfa_secret', status_code=result.status_code)
            self.assertNotContains(result, 'mfa_provisioning_uri', status_code=result.status_code)
            self.assertNotContains(result, created.mfa_secret, status_code=result.status_code)
        updated = self.client.patch(f'/api/users/{created.pk}/', {
            'mfa_confirmed': False,
        }, format='json')
        self.assertEqual(updated.status_code, 200)
        created.refresh_from_db()
        self.assertTrue(created.mfa_confirmed)

    def test_password_only_jwt_endpoint_is_removed(self) -> None:
        response = self.client.post('/api/api/token/', {
            'username': self.user.username, 'password': self.password,
        }, format='json')
        self.assertEqual(response.status_code, 404)

    def test_auth_requests_are_throttled_after_30_requests(self) -> None:
        for _ in range(30):
            response = self.client.post(self.login_url, {
                'username': self.user.username, 'password': 'wrong-password',
            }, format='json')
            self.assertEqual(response.status_code, 401)
        response = self.client.post(self.login_url, {
            'username': self.user.username, 'password': self.password,
        }, format='json')
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response)
        self.assertNotIn('mfa_challenge', response.data)

    def test_user_admin_hides_secret_fields_and_confirmation_is_read_only(self) -> None:
        administrator = User.objects.create_superuser(
            username='root-mfa', email='root-mfa@inacap.cl', password=self.password,
        )
        request = RequestFactory().get('/admin/apiGit/user/')
        request.user = administrator
        registered = admin.site._registry[User]
        sensitive = {
            'mfa_secret', 'mfa_pending_secret', 'mfa_challenge_nonce',
            'mfa_failed_attempts',
        }
        for instance in (None, self.user):
            with self.subTest(add=instance is None):
                form = registered.get_form(request, instance)
                self.assertTrue(sensitive.isdisjoint(form.base_fields))
                self.assertNotIn('mfa_confirmed', form.base_fields)
                fieldsets = str(registered.get_fieldsets(request, instance))
                for name in sensitive:
                    self.assertNotIn(name, fieldsets)
        self.assertIn('mfa_confirmed', registered.get_readonly_fields(request, self.user))
        self.user = administrator
        self.login()  # Being a superuser must not bypass initial API enrollment.

    def test_stale_serializer_update_does_not_restore_consumed_challenge(self) -> None:
        challenge = self.login()
        secret = self.setup_mfa(challenge).data['mfa_secret']
        stale = User.objects.get(pk=self.user.pk)
        serializer = UserSerializer(stale, data={'first_name': 'Updated'}, partial=True)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        code = pyotp.TOTP(secret).now()
        self.assert_tokens(self.submit_code(self.confirm_url, challenge, code))
        serializer.save()
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertTrue(self.user.mfa_confirmed)
        self.assertEqual(self.user.mfa_secret, secret)
        self.assertEqual(self.user.mfa_challenge_nonce, '')
        self.assertEqual(self.user.mfa_pending_secret, '')
        self.assert_rejected(self.submit_code(self.confirm_url, challenge, code))

    def test_stale_admin_save_does_not_restore_consumed_challenge(self) -> None:
        challenge = self.login()
        secret = self.setup_mfa(challenge).data['mfa_secret']
        stale = User.objects.get(pk=self.user.pk)
        registered = admin.site._registry[User]
        administrator = User.objects.create_superuser(
            username='stale-admin', email='stale-admin@inacap.cl', password=self.password,
        )
        request = RequestFactory().post('/admin/apiGit/user/')
        request.user = administrator
        form_class = registered.get_form(request, stale)
        form = form_class(instance=stale)
        code = pyotp.TOTP(secret).now()
        self.assert_tokens(self.submit_code(self.confirm_url, challenge, code))
        stale.first_name = 'Admin update'
        registered.save_model(request, stale, form, change=True)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Admin update')
        self.assertTrue(self.user.mfa_confirmed)
        self.assertEqual(self.user.mfa_secret, secret)
        self.assertEqual(self.user.mfa_pending_secret, '')
        self.assertEqual(self.user.mfa_challenge_nonce, '')
        self.assert_rejected(self.submit_code(self.confirm_url, challenge, code))

    def test_malformed_bearer_does_not_block_password_or_mfa_endpoints(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION='Bearer malformed.jwt')
        challenge = self.login()
        secret = self.setup_mfa(challenge).data['mfa_secret']
        self.assert_tokens(self.submit_code(self.confirm_url, challenge, pyotp.TOTP(secret).now()))
        self.client.credentials(HTTP_AUTHORIZATION='Bearer malformed.jwt')
        challenge = self.login(confirmed=True)
        self.assert_tokens(self.submit_code(self.verify_url, challenge, pyotp.TOTP(secret).now()))

    def test_spoofed_forwarded_for_cannot_evade_direct_access_throttle(self) -> None:
        # Pin direct-access mode regardless of the deployment running this suite.
        with override_settings(REST_FRAMEWORK={**settings.REST_FRAMEWORK, 'NUM_PROXIES': 0}):
            for number in range(30):
                response = self.client.post(self.login_url, {
                    'username': self.user.username, 'password': 'wrong-password',
                }, format='json', HTTP_X_FORWARDED_FOR=f'198.51.100.{number + 1}')
                self.assertEqual(response.status_code, 401)
            response = self.client.post(self.login_url, {
                'username': self.user.username, 'password': self.password,
            }, format='json', HTTP_X_FORWARDED_FOR='203.0.113.200')
            self.assertEqual(response.status_code, 429)
            self.assertNotIn('mfa_challenge', response.data)

    def test_stale_admin_password_form_preserves_newly_confirmed_mfa(self) -> None:
        challenge = self.login()
        secret = self.setup_mfa(challenge).data['mfa_secret']
        stale = User.objects.get(pk=self.user.pk)
        form = admin.site._registry[User].change_password_form(stale, data={
            'password1': 'Replacement-test-password-725!',
            'password2': 'Replacement-test-password-725!',
        })
        self.assertTrue(form.is_valid(), form.errors)
        code = pyotp.TOTP(secret).now()
        self.assert_tokens(self.submit_code(self.confirm_url, challenge, code))
        form.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Replacement-test-password-725!'))
        self.assertTrue(self.user.mfa_confirmed)
        self.assertEqual(self.user.mfa_secret, secret)
        self.assertEqual(self.user.mfa_pending_secret, '')
        self.assertEqual(self.user.mfa_challenge_nonce, '')
        self.assert_rejected(self.submit_code(self.confirm_url, challenge, code))


class MFAEnrollmentMigrationTests(TransactionTestCase):
    """Run the backfill against historical models in Django's isolated test DB."""

    def test_existing_secrets_are_preserved_and_only_they_are_confirmed(self) -> None:
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        # Always restore the schema, including when an assertion fails.
        self.addCleanup(lambda: MigrationExecutor(connection).migrate(latest))
        before = [('apiGit', '0001_initial')]
        after = [('apiGit', '0002_user_mfa_enrollment')]
        executor.migrate(before)
        historical_user = executor.loader.project_state(before).apps.get_model('apiGit', 'User')
        secret = pyotp.random_base32()
        existing = historical_user.objects.create(
            username='legacy-secret', email='legacy-secret@inacap.cl', mfa_secret=secret,
        )
        pending = historical_user.objects.create(
            username='legacy-empty', email='legacy-empty@inacap.cl', mfa_secret='',
        )
        executor = MigrationExecutor(connection)
        executor.migrate(after)
        migrated_user = executor.loader.project_state(after).apps.get_model('apiGit', 'User')
        migrated = migrated_user.objects.get(pk=existing.pk)
        self.assertTrue(migrated.mfa_confirmed)
        self.assertEqual(migrated.mfa_secret, secret)
        self.assertFalse(migrated_user.objects.get(pk=pending.pk).mfa_confirmed)
