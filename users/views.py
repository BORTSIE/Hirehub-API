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
from .serializers import JobSerializer, CompanySerializer, JobApplicationSerializer, NotificationSerializer, SavedJobSerializer, MessageSerializer, ConversationSerializer
from users.services.send_email import send_activation_email
from .models import Company, FoundingInfo, ContactInfo, SocialLinks, Salary , JobApplication, SavedJob, Notification, Message, Conversation  
from django.db.models import Count


  


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
        reset_link = f"http://localhost:5173/auth/reset-password?uid={uidb64}&token={token}"

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
    user = request.user
    profile = user.userprofile

    if profile.user_type != 'EM':
        return Response({"message": "Only employers can post jobs."},
                        status=status.HTTP_403_FORBIDDEN)

    # Ensure employer has a company
    try:
        company = Company.objects.get(contact_info__email=user.email)
    except Company.DoesNotExist:
        return Response({"message": "You must create a company profile before posting jobs."},
                        status=status.HTTP_400_BAD_REQUEST)

    serializer = JobSerializer(data=request.data)
    if serializer.is_valid():
        job = serializer.save(company=company)
        return Response(JobSerializer(job).data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#List all jobs
@api_view(['GET'])
def list_jobs(request):
    jobs = Job.objects.filter(is_deleted=False, is_expired=False)

    #---read query params ----
    company_name = request.request.GET.get('company_name')
    job_type = request.request.GET.get('job_type')
    location = request.request.GET.get('location')
    keyword = request.request.GET.get('keyword')
    tags = request.request.GET.get('tags')

    
    #---filtering logic ----
    if company_name:
        jobs = jobs.filter(company__name__icontains=company_name)

    if job_type:
        jobs = jobs.filter(job_type__iexact=job_type)

    if location:
        jobs = jobs.filter(location__icontains=location)

    if keyword:
        jobs = jobs.filter(models.Q(title__icontains=keyword) | models.Q(description__icontains=keyword))

    if tags:
        tags_list = tags.split(',')
        for tag in tags_list:
            jobs = jobs.filter(tags__icontains=tag)

        
    # --- ordering ---
    ordering = request.GET.get("ordering")
    if ordering == "latest":
        jobs = jobs.order_by("-posted_at")   # newest first
    elif ordering == "oldest":
        jobs = jobs.order_by("posted_at")    # oldest first
    elif ordering == "salary_high":
        jobs = jobs.order_by("-salary__max") # highest salary first
    elif ordering == "salary_low":
        jobs = jobs.order_by("salary__min")  # lowest salary first
    else:
        jobs = jobs.order_by("-posted_at")   # default: latest jobs

    

    #---serialization and response ----
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
    
    
    #Create Company-related models here
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_company(request):
    user = request.user
    try:
        if user.userprofile.user_type != 'EM':
            return Response(
                {"message": "Only employers can create company profiles."},
                status=status.HTTP_403_FORBIDDEN
            )

        data = request.data  # single JSON object

        # ✅ Check if company already exists (by name)
        if Company.objects.filter(name__iexact=data.get("name")).exists():
            return Response(
                {"message": "A company with this name already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # ✅ Or check if this recruiter already created a company
        if Company.objects.filter(contact_info__email=data.get("email")).exists():
            return Response(
                {"message": "A company with this email already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create FoundingInfo
        founding_info = FoundingInfo.objects.create(
            org_type=data.get("org_type"),
            industry_type=data.get("industry_type"),
            team_size=data.get("team_size"),
            year_established=data.get("year_established"),
            company_website=data.get("company_website"),
            company_vision=data.get("company_vision"),
        )

        # Create ContactInfo
        contact_info = ContactInfo.objects.create(
            map_location=data.get("map_location"),
            phone=data.get("phone"),
            email=data.get("email"),
        )

        # Create SocialLinks
        social_links = SocialLinks.objects.create(
            facebook=data.get("facebook"),
            twitter=data.get("twitter"),
            linkedin=data.get("linkedin"),
            instagram=data.get("instagram"),
        )

        # Create Company
        company = Company.objects.create(
            name=data.get("name"),
            logo=data.get("logo"),
            banner_logo=data.get("banner_logo"),
            about_us=data.get("about_us"),
            founding_info=founding_info,
            contact_info=contact_info,
            socials=social_links
        )

        return Response(
            {
                "message": "Company profile created successfully.",
                
                "company_id": company.id
            },
            status=status.HTTP_201_CREATED
        )

    except Exception as e:
        return Response(
            {"message": f"Failed to create company profile: {e}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    
# Get company profile
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_company(request, id):
    try:
        company = Company.objects.get(id=id)
        serializer = CompanySerializer(company)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Company.DoesNotExist:
        return Response({"message": "Company not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"message": f"Failed to retrieve company profile: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# List all companies
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_companies(request):
    try:
        companies = Company.objects.all()
        serializer = CompanySerializer(companies, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"message": f"Failed to retrieve companies: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

#Apply to a job
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def apply_to_job(request, job_id):
    user_profile = request.user.userprofile
    if user_profile.user_type != "JS":
        return Response({"message": "Only job seekers can apply."}, status=status.HTTP_403_FORBIDDEN)

    try:
        job = Job.objects.get(id=job_id, is_deleted=False, is_expired=False)
    except Job.DoesNotExist:
        return Response({"message": "Job not found"}, status=status.HTTP_404_NOT_FOUND)

    # Prevent duplicate applications
    if JobApplication.objects.filter(job=job, applicant=user_profile).exists():
        return Response({"message": "You have already applied for this job."}, status=status.HTTP_400_BAD_REQUEST)

    resume_id = request.data.get("resume_id")
    cover_letter = request.data.get("cover_letter", "")

    resume = None
    if resume_id:
        try:
            resume = Resume.objects.get(id=resume_id, user_profile=user_profile)
        except Resume.DoesNotExist:
            return Response({"message": "Invalid resume ID"}, status=status.HTTP_400_BAD_REQUEST)

    application = JobApplication.objects.create(
        job=job,
        applicant=user_profile,
        resume=resume,
        cover_letter=cover_letter,
    )

    serializer = JobApplicationSerializer(application)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# List applications for a job (recruiter only)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_applications(request, job_id):
    user_profile = request.user.userprofile
    if user_profile.user_type != "EM":
        return Response({"message": "Only employers can view applications."}, status=status.HTTP_403_FORBIDDEN)

    try:
        job = Job.objects.get(id=job_id, company__contact_info__email=request.user.email)
    except Job.DoesNotExist:
        return Response({"message": "Job not found or not owned by you."}, status=status.HTTP_404_NOT_FOUND)

    applications = job.applications.all()
    serializer = JobApplicationSerializer(applications, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

#update application status (recruiter only)
@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def update_application_status(request, application_id):
    user_profile = request.user.userprofile
    if user_profile.user_type != "EM":
        return Response({"message": "Only employers can update application status."}, status=status.HTTP_403_FORBIDDEN)

    try:
        application = JobApplication.objects.get(id=application_id, job__company__contact_info__email=request.user.email)
    except JobApplication.DoesNotExist:
        return Response({"message": "Application not found or not associated with your job."}, status=status.HTTP_404_NOT_FOUND)

    new_status = request.data.get("status")
    if new_status not in dict(JobApplication.STATUS_CHOICES):
        return Response({"message": "Invalid status value."}, status=status.HTTP_400_BAD_REQUEST)

    application.status = new_status
    application.save()

    serializer = JobApplicationSerializer(application)
    return Response(serializer.data, status=status.HTTP_200_OK)


#Save a Job
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_job(request, job_id):
    user_profile = request.user.userprofile
    if user_profile.user_type != "JS":
        return Response({"message": "Only job seekers can save jobs."}, status=status.HTTP_403_FORBIDDEN)

    try:
        job = Job.objects.get(id=job_id, is_deleted=False, is_expired=False)
    except Job.DoesNotExist:
        return Response({"message": "Job not found"}, status=status.HTTP_404_NOT_FOUND)

    # Prevent duplicate saved jobs
    if SavedJob.objects.filter(job=job, user_profile=user_profile).exists():
        return Response({"message": "You have already saved this job."}, status=status.HTTP_400_BAD_REQUEST)

    saved_job = SavedJob.objects.create(
        job=job,
        user_profile=user_profile,
    )

    serializer = SavedJobSerializer(saved_job)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

# List saved jobs for a user
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_saved_jobs(request):
    user_profile = request.user.userprofile
    if user_profile.user_type != "JS":
        return Response({"message": "Only job seekers can view saved jobs."}, status=status.HTTP_403_FORBIDDEN)

    saved_jobs = SavedJob.objects.filter(user_profile=user_profile)
    serializer = SavedJobSerializer(saved_jobs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

#delete a saved job
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_saved_job(request, saved_job_id):
    user_profile = request.user.userprofile
    if user_profile.user_type != "JS":
        return Response({"message": "Only job seekers can delete saved jobs."}, status=status.HTTP_403_FORBIDDEN)

    try:
        saved_job = SavedJob.objects.get(id=saved_job_id, user_profile=user_profile)
    except SavedJob.DoesNotExist:
        return Response({"message": "Saved job not found"}, status=status.HTTP_404_NOT_FOUND)

    saved_job.delete()
    return Response({"message": "Saved job deleted successfully"}, status=status.HTTP_200_OK)

# List notifications for a user
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_notifications(request):
    user_profile = request.user.userprofile

    notifications = Notification.objects.filter(user_profile=user_profile).order_by('-created_at')
    serializer = NotificationSerializer(notifications, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

# Mark a notification as read
@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def mark_notification_as_read(request, notification_id):
    user_profile = request.user.userprofile

    try:
        notification = Notification.objects.get(id=notification_id, user_profile=user_profile)
    except Notification.DoesNotExist:
        return Response({"message": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)

    notification.is_read = True
    notification.save()

    serializer = NotificationSerializer(notification)
    return Response(serializer.data, status=status.HTTP_200_OK)

#Helper function to send email notifications
def notify_new_message(conversation, message):
    participants = conversation.participants.exclude(id=message.sender.id)
    for user in participants:
        try:
            send_mail(
                subject="New Message on HireHub",
                message=f"You have received a new message from {message.sender.username}: {message.content}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Failed to send email to {user.email}: {e}")
    

#List all conversation for the logged-in user
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_conversations(request):
    user = request.user
    conversations = Conversation.objects.filter(participants=user).order_by('-created_at')
    serializer = ConversationSerializer(conversations, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

#Retrieve messages in a conversation
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def retrieve_messages(request, conversation_id):
    user = request.user
    try:
        conversation = Conversation.objects.get(id=conversation_id, participants=user)
    except Conversation.DoesNotExist:
        return Response({"message": "Conversation not found"}, status=status.HTTP_404_NOT_FOUND)

    messages = conversation.messages.all().order_by('timestamp')
    serializer = MessageSerializer(messages, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

#Send a message in a conversation
def send_message(request, conversation_id=None):
    user = request.user
    content = request.data.get("content")
    recipient_id = request.data.get("recipient_id")

    if not content:
        return Response({"message": "Message content is required"}, status=status.HTTP_400_BAD_REQUEST)

    # If conversation_id is provided, use it
    if conversation_id:
        try:
            conversation = Conversation.objects.get(id=conversation_id, participants=user)
        except Conversation.DoesNotExist:
            return Response({"message": "Conversation not found"}, status=status.HTTP_404_NOT_FOUND)
    else:
        # Create or get conversation between user and recipient
        try:
            recipient = User.objects.get(id=recipient_id)
        except User.DoesNotExist:
            return Response({"message": "Recipient not found"}, status=status.HTTP_404_NOT_FOUND)

        conversation = Conversation.objects.filter(participants=user).filter(participants=recipient).first()
        if not conversation:
            conversation = Conversation.objects.create()
            conversation.participants.set([user, recipient])

    message = Message.objects.create(
        conversation=conversation,
        sender=user,
        content=content
    )

    notify_new_message(message)
    serializer = MessageSerializer(message)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

#mark message as read
@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def mark_message_as_read(request, message_id):
    user = request.user
    try:
        message = Message.objects.get(id=message_id, conversation__participants=user)
    except Message.DoesNotExist:
        return Response({"message": "Message not found"}, status=status.HTTP_404_NOT_FOUND)

    message.is_read = True
    message.save()

    serializer = MessageSerializer(message)
    return Response(serializer.data, status=status.HTTP_200_OK)
        

#Employer dashboard analytics view 
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def employer_dashboard(request):
    user_profile = request.user.userprofile
    if user_profile.user_type != "EM":
        return Response({"message": "Only employers can access the dashboard."}, status=status.HTTP_403_FORBIDDEN)

    try:
        # Total jobs posted
        total_jobs = Job.objects.filter(company__contact_info__email=request.user.email, is_deleted=False).count()

        # Total applications received
        total_applications = JobApplication.objects.filter(job__company__contact_info__email=request.user.email).count()

        # Applications by status
        applications_by_status = JobApplication.objects.filter(job__company__contact_info__email=request.user.email) \
            .values('status') \
            .annotate(count=Count('status'))

        status_data = {status: 0 for status, _ in JobApplication.STATUS_CHOICES}
        for entry in applications_by_status:
            status_data[entry['status']] = entry['count']

        # Recent applications (last 5)
        recent_applications = JobApplication.objects.filter(job__company__contact_info__email=request.user.email) \
            .order_by('-applied_at')[:5]
        recent_applications_serializer = JobApplicationSerializer(recent_applications, many=True)

        dashboard_data = {
            "total_jobs_posted": total_jobs,
            "total_applications_received": total_applications,
            "applications_by_status": status_data,
            "recent_applications": recent_applications_serializer.data,
        }

        return Response(dashboard_data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"message": f"Failed to retrieve dashboard data: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Jobseeker dashboard analytics view
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def jobseeker_dashboard(request):
    user_profile = request.user.userprofile
    if user_profile.user_type != "JS":
        return Response({"message": "Only job seekers can access the dashboard."}, status=status.HTTP_403_FORBIDDEN)

    try:
        # Total applications made
        total_applications = JobApplication.objects.filter(applicant=user_profile).count()

        # Applications by status
        applications_by_status = JobApplication.objects.filter(applicant=user_profile) \
            .values('status') \
            .annotate(count=Count('status'))

        status_data = {status: 0 for status, _ in JobApplication.STATUS_CHOICES}
        for entry in applications_by_status:
            status_data[entry['status']] = entry['count']

        # Recent applications (last 5)
        recent_applications = JobApplication.objects.filter(applicant=user_profile) \
            .order_by('-applied_at')[:5]
        recent_applications_serializer = JobApplicationSerializer(recent_applications, many=True)

        dashboard_data = {
            "total_applications_made": total_applications,
            "applications_by_status": status_data,
            "recent_applications": recent_applications_serializer.data,
        }

        return Response(dashboard_data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"message": f"Failed to retrieve dashboard data: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)