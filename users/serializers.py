from rest_framework import serializers
from .models import UserProfile, Resume, SocialLink
from django.contrib.auth.models import User

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)



class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    fullname = serializers.CharField(required=True, write_only=True)
    username = serializers.CharField(required=True, write_only=True)
    user_type = serializers.ChoiceField(required=True, write_only=True, choices=[('JS', 'Job Seeker'), ('EM', 'Employer'), ('AD', 'Admin')])
    password = serializers.CharField(required=True, write_only=True)        
    password2 = serializers.CharField(required=True, write_only=True)
    


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)        
    new_password = serializers.CharField(required=True, write_only=True)        
    new_password2 = serializers.CharField(required=True, write_only=True)


class PasswordRequest(serializers.Serializer):
    uidb64 = serializers.CharField(required=True, write_only=True)
    token = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


class UserProfileSerializer(serializers.ModelSerializer):
    user  = UserSerializer(read_only=True)
    class Meta:
        model = UserProfile
        fields = "__all__"


class ResumeSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer(read_only=True)
    class Meta:
        model = Resume
        fields = "__all__"


class SocialLinkSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer(read_only=True)
    class Meta:
        model = SocialLink
        fields = "__all__"