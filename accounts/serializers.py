from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *

# Serializer for registration endpoint.
class RegisterSerializer(serializers.ModelSerializer):
  
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only':True}}

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        return attrs

    def create(self, validated_data, *args):
        user = User.objects.create_user(**validated_data)
        return user


# Serializer for password change endpoint.
class ChangePasswordSerializer(serializers.Serializer):
    
    model = User
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    


