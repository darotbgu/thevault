from django.contrib.auth.models import User
from django.db import models


class Holocron(models.Model):
    crystal = models.TextField()


class Artifacts(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    holocron = models.ForeignKey(Holocron, on_delete=models.CASCADE)
    jedi = models.TextField()
    sith = models.TextField()
    force = models.TextField()


