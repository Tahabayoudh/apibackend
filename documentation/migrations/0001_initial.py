# Generated by Django 5.1.5 on 2025-01-25 09:39

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('nom_document', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('type_document', models.CharField(max_length=100)),
                ('date_creation', models.DateField(auto_now_add=True)),
                ('date_modification', models.DateField(auto_now=True)),
            ],
        ),
    ]
