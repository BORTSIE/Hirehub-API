from rest_framework import serializers
from .models import UserProfile, Resume, SocialLink, Salary, Company, Job, FoundingInfo, ContactInfo, JobApplication, SavedJob, Notification, Message, Conversation
from django.contrib.auth.models import User



#Login Serializer
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


#Register Serializer
class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    fullname = serializers.CharField(required=True, write_only=True)
    username = serializers.CharField(required=True, write_only=True)
    user_type = serializers.ChoiceField(required=True, write_only=True, choices=[('JS', 'Job Seeker'), ('EM', 'Employer'), ('AD', 'Admin')])
    password = serializers.CharField(required=True, write_only=True)        
    password2 = serializers.CharField(required=True, write_only=True)
    

#Change Password Serializer
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)        
    new_password = serializers.CharField(required=True, write_only=True)        
    new_password2 = serializers.CharField(required=True, write_only=True)

# Reset Password Serializer
class PasswordRequest(serializers.Serializer):
    uidb64 = serializers.CharField(required=True, write_only=True)
    token = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)


# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name']


# UserProfile Serializer
class UserProfileSerializer(serializers.ModelSerializer):
    user  = UserSerializer(read_only=True)
    class Meta:
        model = UserProfile
        fields = "__all__"


# Resume Serializer
class ResumeSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer(read_only=True)
    class Meta:
        model = Resume
        fields = "__all__"


# SocialLink Serializer
class SocialLinkSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer(read_only=True)
    class Meta:
        model = SocialLink
        fields = "__all__"

#forgot password
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


# Change Password Serializer
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)        
    new_password = serializers.CharField(required=True, write_only=True)        
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        if data['new_password'] != data['new_password2']:
            raise serializers.ValidationError("New passwords do not match.")
        return data
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct.")
        return value
    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user
    

# Salary Serializer
class SalarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Salary
        fields = '__all__'

# FoundingInfo Serializer
class FoundingInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = FoundingInfo
        fields = '__all__'

# ContactInfo Serializer
class ContactInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInfo
        fields = '__all__'


# Company Serializer
class CompanySerializer(serializers.ModelSerializer):
    founding_info = FoundingInfoSerializer(read_only=True)
    socials = SocialLinkSerializer(read_only=True)
    contact_info = ContactInfoSerializer(read_only=True)           
    class Meta:
        model = Company
        fields = '__all__'


# Job Serializer
class JobSerializer(serializers.ModelSerializer):
    salary = SalarySerializer()
    company = CompanySerializer()
    
    class Meta:
            model = Job
            fields = '__all__'

def create(self, validated_data):
    salary_data = validated_data.pop('salary')
    company_data = validated_data.pop('company')
    salary = Salary.objects.create(**salary_data)
    company = Company.objects.get(id=company_data[id])
    job = Job.objects.create(salary=salary, company=company, **validated_data)
    return job

def update(self, instance, validated_data):
    salary_data = validated_data.pop('salary', None)
    company_data = validated_data.pop('company', None)

    if salary_data:
        salary_serializer = SalarySerializer(instance.salary, data=salary_data)
        if salary_serializer.is_valid(raise_exception=True):
            salary_serializer.save()

    if company_data:
        company_serializer = CompanySerializer(instance.company, data=company_data)
        if company_serializer.is_valid(raise_exception=True):
            company_serializer.save()

    for attr, value in validated_data.items():
        setattr(instance, attr, value)
    instance.save()
    return instance


#JobApplication Serializer
class JobApplicationSerializer(serializers.ModelSerializer):
    job = JobSerializer(read_only=True)
    user_profile = UserProfileSerializer(read_only=True)
    
    class Meta:
        model = JobApplication
        fields = '__all__'

#SavedJob Serializer
class SavedJobSerializer(serializers.ModelSerializer):
    job = JobSerializer(read_only=True)
    user_profile = UserProfileSerializer(read_only=True)
    
    class Meta:
        model = SavedJob
        fields = '__all__'

#Notification Serializer
class NotificationSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Notification
        fields = '__all__'

#Conversation Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name"]

#Message Serializer
class MessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = Message
        fields = ["id", "conversation", "sender", "content", "is_read", "timestamp"]

#Conversation Serializer
class ConversationSerializer(serializers.ModelSerializer):
    participants = UserSerializer(many=True, read_only=True)
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = ["id", "participants", "created_at", "messages"]
