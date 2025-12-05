from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError

from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model

from .serializers import (
    RegisterSerializer,
    GetOTPSerializer,
    VerifyOTPSerializer,
    LoginSerializer,
    UserDetailSerializer,
    ChangePasswordSerializer,
    ForgotPasswordMobileSerializer,
    PasswordResetOTPVerifySerializer,
    SetNewPasswordSerializer
)

User = get_user_model()

# REGISTER USER
class UserRegisterView(viewsets.ViewSet):

    @action(detail=False, methods=["post"])
    def register(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserDetailSerializer(user).data, status=201)

    def list(self, request):
        users = User.objects.all()
        data = UserDetailSerializer(users, many=True).data
        return Response(data, status=200)

    # GET SINGLE USER BY ID
    def retrieve(self, request, pk=None):
        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=404)

        return Response(UserDetailSerializer(user).data, status=200)


# OTP USING USER ID
class UserOTPViewSet(viewsets.ViewSet):

    def get_user_or_404(self, pk):
        try:
            return User.objects.get(id=pk)
        except User.DoesNotExist:
            raise ValidationError({"detail": "User not found"})

    @action(detail=True, methods=["post"])
    def get_otp(self, request, pk=None):
        serializer = GetOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        mobile = serializer.validated_data["mobile"]
        user = self.get_user_or_404(pk)

        # User already verified → No OTP needed
        if user.is_verified:
            return Response({"detail": "User already verified. OTP not required."}, status=400)

        # Unique mobile must be maintained
        try:
            existing_user = User.objects.get(mobile=mobile)
            if existing_user.id != user.id:
                return Response({"detail": "This mobile number is already linked with another user"}, status=400)
        except User.DoesNotExist:
            pass

        # User cannot change mobile once set
        if user.mobile is not None and user.mobile != mobile:
            return Response({"detail": "This user id not valid"}, status=400)

        # 1-minute rate limit
        if user.otp_expires_at and (timezone.now() - (user.otp_expires_at - timedelta(minutes=1))).seconds < 60:
            return Response({"detail": "Please wait 1 minute before requesting new OTP"}, status=429)

        # Save & generate OTP
        user.mobile = mobile
        otp = user.generate_otp()

        return Response({
            "detail": "OTP sent successfully",
            "user": UserDetailSerializer(user).data,
            "otp": otp
        })

    # -------- VERIFY OTP --------
    @action(detail=True, methods=["post"])
    def verify_otp(self, request, pk=None):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]
        user = self.get_user_or_404(pk)

        if not user.verify_otp(otp):
            return Response({"detail": "Invalid or expired OTP"}, status=400)

        user.is_verified = True
        user.otp = None
        user.otp_expires_at = None
        user.save()

        data = UserDetailSerializer(user).data
        data["mobile"] = None

        return Response(data, status=200)

# LOGIN
class LoginView(viewsets.ViewSet):

    @action(detail=False, methods=["post"])
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)

        return Response({
            "detail": "Login successful",
            "user": UserDetailSerializer(user).data,
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        })

# CHANGE PASSWORD (USER LOGGED-IN + OTP REQUIRED)
class ChangePasswordView(viewsets.ViewSet):

    @action(detail=False, methods=["post"])
    def send_otp(self, request):
        user = request.user

        if not user.is_verified:
            return Response({"detail": "User not verified"}, status=400)

        otp = user.generate_otp()
        return Response({"detail": "OTP sent", "otp": otp})

    @action(detail=False, methods=["post"])
    def verify_otp(self, request):
        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]
        user = request.user

        if not user.verify_otp(otp):
            return Response({"detail": "Invalid or expired OTP"}, status=400)

        user.temp_otp_verified = True
        user.save()

        return Response({"detail": "OTP verified. You can now change password."})

    @action(detail=False, methods=["post"])
    def set_new_password(self, request):
        user = request.user

        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user.password = make_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Password changed successfully"})

# FORGOT PASSWORD
class ForgotPasswordView(viewsets.ViewSet):

    @action(detail=False, methods=["post"])
    def send_otp(self, request):
        serializer = ForgotPasswordMobileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        mobile = serializer.validated_data["mobile"]

        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            return Response({"detail": "Mobile not found"}, status=400)

        if not user.is_verified:
            return Response({"detail": "User not verified. Forgot password not allowed."}, status=400)

        otp = user.generate_otp()

        return Response({"detail": "OTP sent", "otp": otp})

    @action(detail=False, methods=["post"])
    def verify_otp(self, request):
        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]

        # OTP verification must search user
        try:
            user = User.objects.get(otp=otp)
        except User.DoesNotExist:
            return Response({"detail": "Invalid OTP"}, status=400)

        return Response({"detail": "OTP verified. You can now reset password.", "user_id": user.id})

    @action(detail=False, methods=["post"])
    def set_new_password(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = request.data.get("user_id")

        try:
            user = User.objects.get(id=user_id)
        except:
            return Response({"detail": "Invalid request"}, status=400)

        user.password = make_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Password reset successful"})
