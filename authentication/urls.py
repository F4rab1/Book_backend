from django.urls import path
from .views import registration_email_view, registration_email_verify_view, registration_password_view, login_view, \
    logout_view
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('registration/email/', registration_email_view, name='registration-email'),
    path('registration/email-verify/', registration_email_verify_view, name='email-verify'),
    path('registration/password/', registration_password_view, name='registration-password'),
    path('login/', login_view, name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('logout', logout_view, name='logout'),
]