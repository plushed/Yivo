# Generated by Django 5.2 on 2025-04-14 18:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("search", "0005_usermodule_weight"),
    ]

    operations = [
        migrations.AddField(
            model_name="module",
            name="default_weight",
            field=models.DecimalField(decimal_places=2, default=1.0, max_digits=5),
        ),
    ]
