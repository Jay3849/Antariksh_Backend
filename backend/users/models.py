# from django.db import models
# from django.contrib.auth.models import AbstractUser, BaseUserManager
# from django.utils import timezone
# from datetime import timedelta
# import random

# class CustomUserManager(BaseUserManager):
#     def create_user(self, username, password=None, **extra_fields):
#         if not username:
#             raise ValueError("Username is required")

#         user = self.model(username=username, **extra_fields)
#         user.set_password(password)
#         user.save()
#         return user

#     def create_superuser(self, username, password=None, **extra_fields):
#         extra_fields.setdefault("is_staff", True)
#         extra_fields.setdefault("is_superuser", True)
#         return self.create_user(username, password, **extra_fields)


# class CustomUser(AbstractUser):

#     email = None             # REMOVE EMAIL
#     first_name = None
#     last_name = None

#     username = models.CharField(max_length=150, unique=True)
#     mobile = models.CharField(max_length=15, unique=True)

#     otp = models.CharField(max_length=6, blank=True, null=True)
#     otp_expires_at = models.DateTimeField(blank=True, null=True)
#     is_verified = models.BooleanField(default=False)

#     USERNAME_FIELD = "username"
#     REQUIRED_FIELDS = ["mobile"]

#     objects = CustomUserManager()

#     def __str__(self):
#         return self.username

#     # OTP GENERATE
#     def generate_otp(self):
#         otp = str(random.randint(100000, 999999))
#         self.otp = otp
#         self.otp_expires_at = timezone.now() + timedelta(minutes=10)
#         self.save()
#         return otp

#     # OTP VERIFY
#     def verify_otp(self, otp):
#         return (
#             self.otp == otp
#             and self.otp_expires_at
#             and timezone.now() <= self.otp_expires_at
#         )



from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
from datetime import timedelta
import random


class CustomUserManager(BaseUserManager):

    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")

        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(username, password, **extra_fields)


class CustomUser(AbstractUser):

    email = None           # remove email
    first_name = None
    last_name = None

    username = models.CharField(max_length=150, unique=True)
    mobile = models.CharField(max_length=15, unique=True, null=True, blank=True)

    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expires_at = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.username

    def generate_otp(self):
        otp = str(random.randint(100000, 999999))
        self.otp = otp
        self.otp_expires_at = timezone.now() + timedelta(minutes=10)
        self.save()
        return otp

    def verify_otp(self, otp):
        return (
            self.otp == otp and
            self.otp_expires_at and
            timezone.now() <= self.otp_expires_at
        )
