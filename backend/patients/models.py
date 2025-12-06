from django.db import models
from django.conf import settings

class Patient(models.Model):
    # BASIC REQUIRED FIELDS
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField()

    GENDER_CHOICES = [
        ("male", "Male"),
        ("female", "Female"),
        ("other", "Other"),
    ]
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES)

    pincode = models.CharField(max_length=10)

    # LINK EACH PATIENT TO ONE USER
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="patient_profile",
        null=True,
        blank=True
    )

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
