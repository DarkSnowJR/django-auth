from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import (
    AbstractUser, BaseUserManager, PermissionsMixin)


class CustomUserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):

        if email is None:
            raise TypeError("Users should have an Email")

        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if password is None:
            raise TypeError("Password should not be None")

        user = self.create_user(email, password, **extra_fields)
        user = self.model(email=self.normalize_email(email))
        return user


class User(AbstractUser):
    username = models.CharField(
        max_length=255, unique=True, db_index=True, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    email_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    def __str__(self):
        if self.get_full_name():
            name = self.get_full_name()
        else:
            name = self.email
        return name

    # def tokens(self):
    #     refresh = RefreshToken.for_user(self)
    #     return {
    #         'refresh': str(refresh),
    #         'access': str(refresh.access_token)
    #     }
