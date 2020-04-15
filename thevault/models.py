from django.contrib.auth.models import User
from django.db import models


class Site(models.Model):
    name = models.TextField()


class AuthenticationData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    site = models.ForeignKey(Site, on_delete=models.CASCADE)
    username = models.TextField()
    password = models.TextField()


