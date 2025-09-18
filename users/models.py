from django.db import models
from django.contrib.auth.models import User

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
    

class Resume(models.Model):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='resume')
    resume_name = models.CharField(max_length=255)
    resume_file = models.FileField(upload_to='resumes/')
    biography = models.TextField(blank=True)

    def __str__(self):
        return f"{self.user_profile.user.username}'s Resume"
    

class SocialLink(models.Model):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='social_links')
    linkedin = models.URLField(null=True, blank=True)
    github = models.URLField(null=True, blank=True)
    twitter = models.URLField(null=True, blank=True)
    facebook = models.URLField(null=True, blank=True)
    instagram = models.URLField(null=True, blank=True)
    personal_website = models.URLField(null=True, blank=True)

    def __str__(self):
        return f"{self.user_profile.user.username}'s Social Links"

