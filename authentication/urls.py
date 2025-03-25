from django.urls import path
from .views import RegistrationEmailView, RegistrationEmailVerifyView, RegistrationPasswordView, LoginView, \
    LogoutView
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_nested import routers

urlpatterns = [
    path('registration/email/', RegistrationEmailView.as_view(), name='registration-email'),
    path('registration/email-verify/', RegistrationEmailVerifyView.as_view(), name='email-verify'),
    path('registration/password/', RegistrationPasswordView.as_view(), name='registration-password'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('logout', LogoutView.as_view(), name='logout'),
]