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
from .serializers import UserProfileSerializer, ResumeSerializer, SocialLinkSerializer
from django.views.decorators.csrf import csrf_exempt


# Create your views here.



class customTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            if not refresh_token:
                return Response("No refresh token found in cookies.", {"detail": "refresh token was not found in the cookies."}, status.HTTP_401_UNAUTHORIZED)

            request._full_data = request.data.copy()
            request._full_data['refresh'] = refresh_token

            response = super().post(request, *args, **kwargs)

            access_token = response.data['access']

            res = Response("Token has been refrshed", { "refreshed": True, "token": access_token })

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
            return Response("An unexpected error occured", { "refreshed": False, "message":f"{e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       


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

        if not check_password(password, user.password):
            return Response(
                {"message": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        auth_login(request, user)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = Response(
            {
                "message": "Login successful",
                "authenticated": True,
                "access_token": access_token
                    
                
            },
            status=status.HTTP_200_OK
        )

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

@api_view(["POST"])
@authentication_classes([])
def register(request):

    serializer = RegisterSerializer(data = request.data)

    if not serializer.is_valid():
        return Response(
            {"message": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    first_name = serializer.validated_data["first_name"]
    last_name = serializer.validated_data["last_name"]
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
            

        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password
        )

        UserProfile.objects.create(
            user=user,
            user_type=user_type
        )
        

        return Response({ "message": "User registered successfully." }, status=status.HTTP_201_CREATED)
        

    except Exception as e:
        return Response({ "message": f"Failed to registrater user {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       


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
        links.personal_website = request.data.get("personal_website", links.personal_website)    
        links.save()
        return Response({"status": "success", "message": "Social links saved"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": f"Failed to save social links: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)