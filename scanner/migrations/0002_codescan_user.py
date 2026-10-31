from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("scanner", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="codescan",
            name="user",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="code_scans",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
