from rest_framework import serializers
from .models import UserCustomer
from django.contrib.auth import authenticate
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCustomer
        fields = '__all__'