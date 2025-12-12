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

class ChangePasswordView(viewsets.ViewSet):

    def _get_user_by_url(self, pk):
        try:
            return User.objects.get(id=pk)
        except User.DoesNotExist:
            raise ValidationError({"detail": "User not found"})

    def _validate_logged_in_user(self, request, pk):
        # 1️⃣ Must be logged-in
        if not request.user or not request.user.is_authenticated:
            raise ValidationError({"detail": "Authentication required"})

        url_user = self._get_user_by_url(pk)
        logged_user = request.user

        # 2️⃣ URL user must match logged-in user
        if url_user.id != logged_user.id:
            raise ValidationError({"detail": "This user id not valid"})

        # 3️⃣ User must be verified
        if not logged_user.is_verified:
            raise ValidationError({"detail": "User is not verified"})

        # 4️⃣ Mobile must be linked
        if not logged_user.mobile:
            raise ValidationError({"detail": "Mobile number not linked to this account"})

        return logged_user

    # STEP 1: SEND OTP
    @action(detail=True, methods=["post"])
    def send_otp(self, request, pk=None):
        user = self._validate_logged_in_user(request, pk)

        otp = user.generate_otp()
        return Response({"detail": "OTP sent", "otp": otp}, status=200)

    # STEP 2: VERIFY OTP
    @action(detail=True, methods=["post"])
    def verify_otp(self, request, pk=None):
        user = self._validate_logged_in_user(request, pk)

        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data["otp"]

        if not user.verify_otp(otp):
            return Response({"detail": "Invalid or expired OTP"}, status=400)

        # Store temporary flag
        request.session["password_otp_verified"] = True
        request.session.modified = True

        return Response({"detail": "OTP verified. You can now change password."})

    # STEP 3: SET NEW PASSWORD
    @action(detail=True, methods=["post"])
    def set_new_password(self, request, pk=None):
        user = self._validate_logged_in_user(request, pk)

        if not request.session.get("password_otp_verified"):
            return Response({"detail": "OTP verification required"}, status=400)

        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_password = serializer.validated_data["new_password"]

        if user.check_password(new_password):
            return Response({"detail": "New password cannot be same as old password"}, status=400)

        user.password = make_password(new_password)
        user.save()

        # Clear session
        request.session.pop("password_otp_verified", None)

        return Response({"detail": "Password changed successfully"})


# FORGOT PASSWORD
class ForgotPasswordView(viewsets.ViewSet):

    # STEP 1 → SEND OTP
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
        return Response({"detail": "OTP sent", "otp": otp}, status=200)

    # STEP 2 → VERIFY OTP
    @action(detail=False, methods=["post"])
    def verify_otp(self, request):
        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]

        # Find user by OTP + verify OTP expiration
        try:
            user = User.objects.get(otp=otp)
        except User.DoesNotExist:
            return Response({"detail": "Invalid OTP"}, status=400)

        if not user.verify_otp(otp):
            return Response({"detail": "Invalid or expired OTP"}, status=400)

        return Response({
            "detail": "OTP verified. You can now reset password.",
            "user_id": user.id
        }, status=200)

    # STEP 3 → SET NEW PASSWORD
    @action(detail=False, methods=["post"])
    def set_new_password(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = request.data.get("user_id")
        if not user_id:
            return Response({"detail": "user_id is required"}, status=400)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"detail": "Invalid user"}, status=400)

        new_password = serializer.validated_data["new_password"]

        user.password = make_password(new_password)
        user.save()

        return Response({"detail": "Password reset successful"}, status=200)
