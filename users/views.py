from django.shortcuts import render
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework import status
from django.contrib.auth import login as auth_login, get_user_model, authenticate
from django.contrib import auth
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from rest_framework.throttling import UserRateThrottle
from rest_framework.decorators import throttle_classes
from rest_framework.response import Response
from .serializers import LoginSerializer, RegisterSerializer
from .models import UserProfile, Resume, SocialLink
from .serializers import UserProfileSerializer, ResumeSerializer, SocialLinkSerializer, ForgotPasswordSerializer, PasswordRequest
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from .serializers import ChangePasswordSerializer
from django.db import models
from .models import Job
from .serializers import JobSerializer
from users.services.send_email import send_activation_email
  


# Create your views here.


# Custom Token Refresh View to read refresh token from HttpOnly cookie
class customTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            if not refresh_token:
                return Response({
                    "detail": "refresh token was not found in the cookies."
                }, status=status.HTTP_401_UNAUTHORIZED)

            request._full_data = request.data.copy()
            request._full_data['refresh'] = refresh_token

            response = super().post(request, *args, **kwargs)

            access_token = response.data['access']

            res = Response({"message":"Token has been refrshed", "refreshed": True})

            res.set_cookie(
                key="access_token",
                value=access_token,
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                max_age=60 * 10,
            )

            res.set_cookie(
                key="isLoggedIn",
                value=True,
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                max_age=60 * 10,
            )

            return res

        except Exception as e:
            return Response({
                "messag": f"An unexpected error occured {e}", 
                "refreshed": False,
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       

# Login
@api_view(["POST"])
@authentication_classes([])
def login(request):
    serializer = LoginSerializer(data=request.data)
    try:
        if not serializer.is_valid():
            return Response(
                {"message": "Validation failed", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response(
                {"message": "Email is not associated with any user"},
                status=status.HTTP_404_NOT_FOUND
            )
        

        try:
            user_account = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({"message": "user does not have any account"},status=status.HTTP_404_NOT_FOUND)

        if not user.is_active:
            return Response(
                {"message": "Account is not activated. Please check your email."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not check_password(password, user.password):
            return Response(
                {"message": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST
            )

        auth_login(request, user)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = Response({
                "message": "Login successful",
                "authenticated": True,
                "access_token": access_token 
            },status=status.HTTP_200_OK)

        cookie_settings = {
            "path": "/",
            "samesite": "None",
            "secure": True,
            "httponly": True,
        }

        response.set_cookie("access_token", access_token, max_age=60*10, **cookie_settings)
        response.set_cookie("refresh_token", str(refresh), max_age=60*60*24*7, **cookie_settings)
        response.set_cookie("is_loggedIn", True, max_age=60*10, **cookie_settings)

        return response
    except Exception as e:
        return Response(
            {"message": "An unexpected error occurred", "details": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Register
@api_view(["POST"])
@authentication_classes([])
def register(request):

    serializer = RegisterSerializer(data = request.data)

    if not serializer.is_valid():
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    full_name = serializer.validated_data["fullname"]
    username = serializer.validated_data["username"]
    user_type = serializer.validated_data["user_type"]
    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]
    password2 = serializer.validated_data["password2"]

    try:

        if password != password2:
            return Response( { "message": "Password and confirm password do not match."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response( {"message" : "User with this email already exists! "}, status=status.HTTP_409_CONFLICT)
            

        if User.objects.filter(username=username).exists():
            return Response( {"message" : "Username already in use"}, status=status.HTTP_409_CONFLICT)
            


        # Create the user
        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=full_name,
            password=password,
            is_active=False
        )

        
            
        # Create associated UserProfile
        UserProfile.objects.create(
            user=user,
            user_type=user_type,
            full_name=full_name
        )
        
        
        send_activation_email(user) 
        return Response(
                { "message": "User registered successfully. Please check your email to activate your account." },
                status=status.HTTP_201_CREATED
            )
        

    except Exception as e:
        return Response({ "message": f"Failed to registrater user {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       

# Activate Account
@api_view(["POST"])
@authentication_classes([])
@permission_classes([])
def activate_account(request):
    try:
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        try:
            if not uidb64 or not token:
                return Response({"message": "uid and token are required."}, status=status.HTTP_400_BAD_REQUEST)
            
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Account activated successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid activation link."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"message": f"An unexpected error occured {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

# Logout
@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        auth.logout(request)

        res = Response("You logged out successfully", { "authenticated": False })

        cookie_settings = { "path": "/", "samesite": "None" }

        res.delete_cookie(
            key="access_token",
            **cookie_settings
        )
        res.delete_cookie(
            key="refresh_token", 
            **cookie_settings
        )
        res.delete_cookie(
            key="isLoggedIn", 
            **cookie_settings
        )

        return res

    except Exception as e:
        return Response("An unexpected error occured", { "message": f"Failed to logout user {e}", }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Get authentication status
@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_authentication(request):
    try:

        return Response("authenticated", { "auth": True, })

    except Exception as e:
        return Response("An unexpected error occured", { "message": "Failed to get authentication status", }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)     


           
#Get social link
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_socail_links(request):
    socail_links =request.user.userprofile.social_links
    serializer = SocialLinkSerializer(socail_links)
    return Response(serializer.data)


# Save user profile
@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_user_profile(request):
    user = request.user
    try:
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({"status": "error", "message": "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        profile.full_name = request.data.get("full_name", profile.full_name)
        profile.bio = request.data.get("bio", profile.bio)
        profile.location = request.data.get("location", profile.location)
        profile.birth_date = request.data.get("birth_date", profile.birth_date)
        profile.experience = request.data.get("experience", profile.experience)
        profile.education = request.data.get("education", profile.education)
        profile.nationality = request.data.get("nationality", profile.nationality)
        profile.gender = request.data.get("gender", profile.gender)
        
        if "profile_image" in request.FILES:
            profile.profile_image = request.FILES["profile_image"]    
        profile.save()
        return Response({"status": "success", "message": "Profile saved"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": f"Failed to save profile: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Save resume
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_resume(request):
    user = request.user
    try:
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({"status": "error", "message": "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        resume= Resume.objects.create(user_profile=profile)    
        resume.resume_name = request.data.get("resume_name", resume.resume_name)
        resume.biography = request.data.get("biography", resume.biography)    
        if "resume_file" in request.FILES:
            resume.resume_file = request.FILES["resume_file"]    
        resume.save()
        return Response({"status": "success", "message": "Resume saved"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": f"Failed to save resume: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Save social links
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_social_links(request):
    user = request.user
    try:
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({"status": "error", "message": "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        links = SocialLink.objects.create(user_profile=profile)    
        links.linkedin = request.data.get("linkedin", links.linkedin)
        links.github = request.data.get("github", links.github)
        links.twitter = request.data.get("twitter", links.twitter)
        links.facebook = request.data.get("facebook", links.facebook)
        links.instagram = request.data.get("instagram", links.instagram)
        links.youtube = request.data.get("youtube", links.youtube)
        links.personal_website = request.data.get("personal_website", links.personal_website)    
        links.save()
        return Response({"status": "success", "message": "Social links saved"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": f"Failed to save social links: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Get user profile
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user(request):
    user = request.user
    try:
        profile = UserProfile.objects.get(user=user)
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except UserProfile.DoesNotExist:
        return Response({"status": "error", "message": "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": f"Failed to retrieve profile: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   
    

# Forgot Password
@api_view(["POST"])
@authentication_classes([])
@permission_classes([])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    email = serializer.validated_data["email"]

    try:
        user = get_user_model().objects.get(email=email)
    except get_user_model().DoesNotExist:
        return Response(
            {"message": "Email is not associated with any user"},
            status=status.HTTP_404_NOT_FOUND
        )
    
    try:
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"http://localhost:5173/auth/reset-password?uid={uidb64}&token={token}/"

        send_mail(
            subject="Password Reset Request",
            message=f"Click the link to reset your password: {reset_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"message": f"Failed to send password reset email: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

# Reset Password
@api_view(["POST"])
@authentication_classes([]) 
@permission_classes([])
def reset_password(request):
    serializer = PasswordRequest(data=request.data)
    if not serializer.is_valid():
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    uidb64 = serializer.validated_data["uidb64"]
    token = serializer.validated_data["token"]
    new_password = serializer.validated_data["new_password"]
    new_password2 = serializer.validated_data["new_password2"]

    if new_password != new_password2:
        return Response( { "message": "New password and confirm password do not match."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({"message": "Password validation error", "errors": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
    else:
        return Response({"message": "Invalid token or user ID."}, status=status.HTTP_400_BAD_REQUEST)
    
# Change Password
User = get_user_model()

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    serializer = ChangePasswordSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    old_password = serializer.validated_data["old_password"]
    new_password = serializer.validated_data["new_password"]
    new_password2 = serializer.validated_data["new_password2"]

    if new_password != new_password2:
        return Response( { "message": "New password and confirm password do not match."}, status=status.HTTP_400_BAD_REQUEST)

    if not user.check_password(old_password):
        return Response( { "message": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_password(new_password, user)
    except ValidationError as e:
        return Response({"message": "Password validation error", "errors": e.messages}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()
    return Response({"message": "Password has been changed successfully."}, status=status.HTTP_200_OK)


#Create a job
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_job(request):
    serializer = JobSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#List all jobs
@api_view(['GET'])
def list_jobs(request):
    jobs = Job.objects.all()
    serializer = JobSerializer(jobs, many=True)
    return Response(serializer.data)

#Retrieve a specific job
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def retrieve_job(request, pk):
    try:
        job = Job.objects.get(pk=pk, is_deleted=False) 
    except Job.DoesNotExist:
        return Response({"message": "Job not found"}, status=status.HTTP_404_NOT_FOUND)
    
    serializer = JobSerializer(job)
    return Response(serializer.data)

#Update a specific job
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_job(request, pk):
    try:
        job = Job.objects.get(pk=pk, is_deleted=False) 
    except Job.DoesNotExist:
        return Response({"message": "Job not found"}, status=status.HTTP_404_NOT_FOUND)
    
    serializer = JobSerializer(job, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Soft delete a specific job
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_job(request, pk):
    try:
        job = Job.objects.get(pk=pk, is_deleted=False) 
    except Job.DoesNotExist:
        return Response({"message": "Job not found"}, status=status.HTTP_404_NOT_FOUND)
    
    job.is_deleted = True
    job.deleted_at = timezone.now()
    job.save()
    return Response({"message": "Job deleted successfully"}, status=status.HTTP_200_OK)

@api_view(['POST'])
def resend_activation_email(request, email):
    try:
        if not email:
            return Response({"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        user = get_user_model().objects.get(email=email)
        if user.is_active:
            return Response({"message": "Account is already activated."}, status=status.HTTP_400_BAD_REQUEST)
        
        send_activation_email(user)
        return Response({"message": "Activation email resent successfully."}, status=status.HTTP_200_OK)
    except get_user_model().DoesNotExist:
        return Response({"message": "Email is not associated with any user"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"message": f"Failed to resend activation email: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)