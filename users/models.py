from django.db import models
from django.contrib.auth.models import User
import uuid

# UserProfile Model
class UserProfile(models.Model):
    class user_type(models.TextChoices):
        JOB_SEEKER = 'JS', 'Job Seeker'
        EMPLOYER = 'EM', 'Employer'
        ADMIN = 'AD', 'Admin'

    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='userprofile')
    user_type = models.CharField(max_length=2, choices=user_type.choices, default=user_type.JOB_SEEKER)
    bio = models.TextField(blank=True)
    location = models.CharField(max_length=100, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    full_name = models.CharField(max_length=100, blank=True)
    experience = models.TextField(blank=True)
    education = models.TextField(blank=True)
    nationality = models.CharField(max_length=50, blank=True)
    gender = models.CharField(max_length=10, blank=True)

    def __str__(self):
        return self.user.username
    

# Resume Model
class Resume(models.Model):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='resume')
    resume_name = models.CharField(max_length=255)
    resume_file = models.FileField(upload_to='resumes/')
    biography = models.TextField(blank=True)

    def __str__(self):
        return f"{self.user_profile.user.username}'s Resume"
    

# SocialLink Model
class SocialLink(models.Model):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='social_links')
    linkedin = models.URLField(null=True, blank=True)
    github = models.URLField(null=True, blank=True)
    twitter = models.URLField(null=True, blank=True)
    facebook = models.URLField(null=True, blank=True)
    instagram = models.URLField(null=True, blank=True)
    youtube = models.URLField(null=True, blank=True)
    personal_website = models.URLField(null=True, blank=True)

    def __str__(self):
        return f"{self.user_profile.user.username}'s Social Links"




"""
These models belong to the Company entity (for user_type = Employer).

Since our project uses a single `users` app to manage all user-related data,
we are defining Company-specific models (Company, FoundingInfo, ContactInfo, etc.)
here to keep everything centralized and consistent.

"""

# Salary Model
class Salary(models.Model):
    min = models.PositiveIntegerField()
    max = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.min} - {self.max}"



# Founding Info Model
class FoundingInfo(models.Model):
    org_type = models.TextField(blank=True, null=True)
    industry_type = models.TextField(blank=True, null=True)
    team_size = models.CharField(max_length=50)
    year_established = models.PositiveIntegerField()
    company_website = models.URLField(blank=True, null=True)
    company_vision = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.org_type} - {self.industry_type}"


# Contact Info Model
class ContactInfo(models.Model):
    map_location = models.CharField(max_length=255, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)

    def __str__(self):
        return self.email if self.email else "Contact Info"


# Social Links Model
class SocialLinks(models.Model):
    facebook = models.URLField(blank=True, null=True)
    twitter = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    instagram = models.URLField(blank=True, null=True)

    def __str__(self):
        return f"Social Links"


# Company Model
class Company(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to="logos/", blank=True, null=True)
    banner_logo = models.ImageField(upload_to="banners/", blank=True, null=True)
    about_us = models.TextField()

    founding_info = models.OneToOneField(
        FoundingInfo, on_delete=models.CASCADE, related_name="company"
    )
    socials = models.OneToOneField(
        SocialLinks, on_delete=models.CASCADE, related_name="company", null=True, blank=True
    )
    contact_info = models.OneToOneField(
        ContactInfo, on_delete=models.CASCADE, related_name="company"
    )

    def __str__(self):
        return self.name



# Job Model
class Job(models.Model):
    JOB_TYPES = [
        ("PART-TIME", "Part-Time"),
        ("FULL-TIME", "Full-Time"),
        ("CONTRACT", "Contract"),
        ("INTERNSHIP", "Internship"),
    ]

    JOB_LEVELS = [
        ("JUNIOR", "Junior"),
        ("MID", "Mid"),
        ("SENIOR", "Senior"),
        ("LEAD", "Lead"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    title = models.CharField(max_length=255)
    type = models.CharField(max_length=20, choices=JOB_TYPES)
    level = models.CharField(max_length=20, choices=JOB_LEVELS, blank=True, null=True)
    salary = models.OneToOneField(Salary, on_delete=models.CASCADE)
    description = models.TextField()

    requirements = models.JSONField(default=list)
    desirable = models.JSONField(default=list)
    benefits = models.JSONField(default=list)
    tags = models.JSONField(default=list)

    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="jobs")
    posted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_expired = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
