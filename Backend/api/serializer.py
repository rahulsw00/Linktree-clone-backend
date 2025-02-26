
from django.contrib.auth.password_validation import validate_password
from django.core import validators
from django.contrib.auth.models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields= ['email', 'username', 'password']
        extra_kwargs = {"password": {"write_only": True, "validators": [validate_password]}}
    
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class ResetPasswordSerializer(serializers.Serializer):
    class Meta:
        fields = ['email']