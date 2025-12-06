from rest_framework import serializers
from datetime import date
from .models import Patient


class PatientSerializer(serializers.ModelSerializer):

    class Meta:
        model = Patient
        fields = [
            "id",
            "first_name",
            "last_name",
            "date_of_birth",
            "gender",
            "pincode",
            "user",
        ]
        read_only_fields = ["user"]

    # ---------------------------
    # FIELD-LEVEL VALIDATION
    # ---------------------------

    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name should contain only letters.")
        return value.capitalize()

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name should contain only letters.")
        return value.capitalize()

    def validate_date_of_birth(self, value):
        if value > date.today():
            raise serializers.ValidationError("Date of birth cannot be in the future.")

        age = (date.today() - value).days / 365
        if age > 120:
            raise serializers.ValidationError("Age cannot be more than 120 years.")
        return value

    def validate_gender(self, value):
        valid_choices = [choice[0] for choice in Patient.GENDER_CHOICES]
        if value.lower() not in valid_choices:
            raise serializers.ValidationError(
                f"Gender must be one of: {', '.join(valid_choices)}"
            )
        return value.lower()

    def validate_pincode(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Pincode must be a 6-digit number.")
        return value

    # ---------------------------
    # OBJECT-LEVEL VALIDATION
    # ---------------------------
    def validate(self, attrs):
        if attrs.get("first_name") and attrs.get("last_name"):
            if attrs["first_name"].lower() == attrs["last_name"].lower():
                raise serializers.ValidationError(
                    "First and last name cannot be the same."
                )
        return attrs

    # ---------------------------
    # CREATE METHOD
    # ---------------------------
    def create(self, validated_data):
        user = self.context["request"].user

        # Create empty patient object with user
        p = Patient(user=user)

        # Set only relevant fields
        for field in ("first_name", "last_name", "date_of_birth", "gender", "pincode"):
            if field in validated_data:
                setattr(p, field, validated_data[field])

        p.save()
        return p

    # ---------------------------
    # UPDATE METHOD
    # ---------------------------
   # ---------------------------
# UPDATE METHOD
# ---------------------------

    def update(self, instance, validated_data):
        allowed_fields = ["first_name", "last_name", "date_of_birth", "pincode"]

        for field in allowed_fields:
            if field in validated_data:
                setattr(instance, field, validated_data[field])

        instance.save()
        return instance
