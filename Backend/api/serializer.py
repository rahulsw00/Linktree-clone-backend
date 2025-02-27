
from django.contrib.auth.password_validation import validate_password
from django.core import validators
from django.contrib.auth.models import User
from rest_framework import serializers
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator 

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields= ['email', 'username', 'password']
        extra_kwargs = {"password": {"write_only": True, "validators": [validate_password]}}
    
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class EmailSerializer(serializers.Serializer):

    email = serializers.EmailField()

    class Meta:
        fields = ["email",]



class ResetPasswordSerializer(serializers.Serializer):
    
    password = serializers.CharField(
        write_only=True,
        min_length=1,
    )

    class Meta:
        field = ("password")

    def validate(self, data):
        
        password = data.get("password")
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing data.")

        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = User.objects.get(pk=pk)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("The reset token is invalid")

        user.set_password(password)
        user.save()
        return data