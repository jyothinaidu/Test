# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-07-15 18:27
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_auto_20180715_2354'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='address1',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='address2',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='gender',
            field=models.CharField(choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], default=django.utils.timezone.now, max_length=6),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='language_id',
            field=models.CharField(db_index=True, default=django.utils.timezone.now, max_length=20),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='news_letter',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='nickname',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='password',
            field=models.CharField(default=django.utils.timezone.now, max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='phone1',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='phone2',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='registration_activity_id',
            field=models.CharField(default=django.utils.timezone.now, max_length=200),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='registration_source',
            field=models.CharField(choices=[('Google', 'Google'), ('Facebook', 'Facebook'), ('Github', 'Github'), ('Other', 'Other')], default=django.utils.timezone.now, max_length=100),
            preserve_default=False,
        ),
    ]
