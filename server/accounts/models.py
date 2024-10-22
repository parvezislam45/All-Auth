from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken


class User(AbstractUser):
    username = models.CharField(max_length=100, null=True, blank=True, unique=True)
    email = models.EmailField(max_length=100, unique=True, db_index=True)
    full_name = models.CharField(max_length=100, null=True, blank=True)
    role = models.CharField(max_length=20, default='user')
    
    def __str__(self) -> str:
        return self.username

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
