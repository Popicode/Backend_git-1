from django.db import migrations, models


def confirm_existing_secrets(apps, schema_editor) -> None:
    """Preserve enrollment for existing users who already have a TOTP secret."""
    user_model = apps.get_model('apiGit', 'User')
    user_model.objects.using(schema_editor.connection.alias).exclude(
        mfa_secret='',
    ).filter(mfa_secret__isnull=False).update(mfa_confirmed=True)


class Migration(migrations.Migration):
    dependencies = [('apiGit', '0001_initial')]

    operations = [
        migrations.AddField(
            model_name='user', name='mfa_confirmed',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user', name='mfa_pending_secret',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='user', name='mfa_challenge_nonce',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='user', name='mfa_failed_attempts',
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.RunPython(confirm_existing_secrets, migrations.RunPython.noop),
    ]
