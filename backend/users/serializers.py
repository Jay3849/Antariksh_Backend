from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth import authenticate, get_user_model

User = get_user_model()

# REGISTER SERIALIZER
class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["username", "password", "confirm_password"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise ValidationError({"detail": "Passwords do not match"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        return User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"]
        )

# GET OTP SERIALIZER
class GetOTPSerializer(serializers.Serializer):
    mobile = serializers.CharField()

# VERIFY OTP SERIALIZER
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()

# LOGIN SERIALIZER
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(
            username=data["username"],
            password=data["password"]
        )
        if not user:
            raise ValidationError({"detail": "Invalid username or password"})

        if not user.is_verified:
            raise ValidationError({"detail": "User not verified. Please verify OTP."})

        return user

# USER DETAIL SERIALIZER
class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "mobile", "is_verified"]

# CHANGE PASSWORD REQUEST SERIALIZER
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise ValidationError({"detail": "New passwords do not match"})
        return attrs

# FORGOT PASSWORD REQUEST SERIALIZER

class ForgotPasswordMobileSerializer(serializers.Serializer):
    mobile = serializers.CharField()

# OTP VERIFY FOR PASSWORD RESET
class PasswordResetOTPVerifySerializer(serializers.Serializer):
    otp = serializers.CharField()

# SET NEW PASSWORD AFTER OTP VERIFIED
class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise ValidationError({"detail": "Passwords do not match"})
        return attrs
