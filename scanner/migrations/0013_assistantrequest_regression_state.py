from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("scanner", "0012_organization_plan")]

    operations = [
        migrations.AddField(
            model_name="assistantrequest",
            name="regression_status",
            field=models.CharField(
                choices=[("NOT_RUN", "Not run"), ("PASSED", "Passed"), ("FAILED", "Failed")],
                default="NOT_RUN",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="assistantrequest",
            name="regression_result",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
