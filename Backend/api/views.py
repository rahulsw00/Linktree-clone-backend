from django.shortcuts import render
from rest_framework import generics, status, response
from django.urls import reverse
from django.contrib.auth.models import User
from .serializer import UserSerializer, ResetPasswordSerializer
from rest_framework.permissions import IsAdminUser, AllowAny
from base64 import urlsafe_b64encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# Create your views here.


class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

class RequestPasswordReset(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        user = User.objects.filter(email = email).first()
        if user:
            encoded_pk = urlsafe_b64encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)

            reset_url = reverse(
                "forgot_password",
                kwargs = {"encoded_pk": encoded_pk, "token": token}
            )

            reset_url = f"localhost:8000{reset_url}"

            return response.Response(
                {"message": f"password reset link: {reset_url}"},
                status = status.HTTP_200_OK,
            )
    
        else:
            return response.Response(
                {"message": "user does not exist"},
                status = status.HTTP_400_BAD_REQUEST,
            )