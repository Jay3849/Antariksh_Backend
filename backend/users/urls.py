from django.urls import path
from .views import (
    UserRegisterView,
    UserOTPViewSet,
    LoginView,
    ChangePasswordView,
    ForgotPasswordView
)
# REGISTER
users = UserRegisterView.as_view({
    'post': 'register'
})

# LOGIN
login = LoginView.as_view({
    'post': 'login'
})
# GET all users
users = UserRegisterView.as_view({
    'get': 'list'
})

# GET single user
user_detail = UserRegisterView.as_view({
    'get': 'retrieve'
})

# OTP (using pk)
get_otp = UserOTPViewSet.as_view({
    'post': 'get_otp'
})

verify_otp = UserOTPViewSet.as_view({
    'post': 'verify_otp'
})

resend_otp = UserOTPViewSet.as_view({
    'post': 'resend_otp'
})

# CHANGE PASSWORD (Logged-in)
change_password_send_otp = ChangePasswordView.as_view({
    'post': 'send_otp'
})

change_password_verify_otp = ChangePasswordView.as_view({
    'post': 'verify_otp'
})

change_password_set_password = ChangePasswordView.as_view({
    'post': 'set_new_password'
})

# FORGOT PASSWORD
forgot_send_otp = ForgotPasswordView.as_view({
    'post': 'send_otp'
})

forgot_verify_otp = ForgotPasswordView.as_view({
    'post': 'verify_otp'
})

forgot_set_password = ForgotPasswordView.as_view({
    'post': 'set_new_password'
})

urlpatterns = [
    # Register user
    path('', users, name='users'),
    path('<int:pk>/', user_detail, name='user-detail'),

    # Login
    path('login/', login, name='login'),

    # OTP operations for register/verify
    path('<int:pk>/get-otp/', get_otp, name='get-otp'),
    path('<int:pk>/verify-otp/', verify_otp, name='verify-otp'),
    path('<int:pk>/resend-otp/', resend_otp, name='resend-otp'),

    # Change Password (logged-in)
    path('<int:pk>/change-password/send-otp/', change_password_send_otp, name='change-password-send-otp'),
    path('<int:pk>/change-password/verify-otp/', change_password_verify_otp, name='change-password-verify-otp'),
    path('<int:pk>/change-password/set-new-password/', change_password_set_password, name='change-password-set-password'),

    # Forgot Password
    path('forgot-password/send-otp/', forgot_send_otp, name='forgot-password-send-otp'),
    path('forgot-password/verify-otp/', forgot_verify_otp, name='forgot-password-verify-otp'),
    path('forgot-password/set-new-password/', forgot_set_password, name='forgot-password-set-password'),
]
