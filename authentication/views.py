from rest_framework import status
from rest_framework.response import Response
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
import jwt
from .serializers import RegistrationEmailSerializer, RegistrationPasswordSerializer
from .models import User
from django.conf import settings
from django.core.mail import send_mail, BadHeaderError


class RegistrationEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"ok"})

    def post(self, request):
        try:
            user = User.objects.get(email=request.data['email'])
            if user.is_verified:
                return Response({"error": "User with this email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            serializer = RegistrationEmailSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absolute_link = f"http://{current_site}{relative_link}?token={token}"

        try:
            send_mail('Verify your email', f"Hi from Book.com! Use the link below to verify your email \n {absolute_link}", "book@gmail.com", [f"{request.data['email']}"])
        except BadHeaderError:
            return Response({"error": "Invalid header"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"email": user.email, "message": "verification link sent to your email"}, status=status.HTTP_201_CREATED)


class RegistrationEmailVerifyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get('token')
        if not token:
            return Response({"error": "Token is missing"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({"email": user.email, "verified": True})
        except jwt.exceptions.ExpiredSignatureError:
            return Response({"error": "Token is expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.InvalidTokenError:
            return Response({"error": "Token is invalid"}, status=status.HTTP_400_BAD_REQUEST)


class RegistrationPasswordView(APIView):
    permission_classes = [AllowAny]

    def put(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        if not token:
            return Response({"error": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token is expired"}, status=status.HTTP_400_BAD_REQUEST)
        except (jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"error": "Token is invalid"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_verified:
            return Response({"error": "User is not verified. Please verify your email before setting a password."}, status=status.HTTP_403_FORBIDDEN)

        serializer = RegistrationPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_password = serializer.validated_data['password']
        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not password:
            return Response({"error": "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, password=password)
        if user is None:
            return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        return Response({
            "access": str(access_token),
            "refresh": str(refresh)
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response(
                    {"error": "refresh_token is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
