from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class UserCustomer(AbstractUser):
    description = models.TextField(max_length=500,blank=True)