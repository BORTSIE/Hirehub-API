from django.contrib import admin
from .models import UserProfile, Resume, SocialLink


 
@admin.register(UserProfile)
class userprofile(admin.ModelAdmin):
    list_display = ('user', 'user_type', 'location', 'birth_date', 'full_name', 'nationality', 'experience', 'education', 'gender', 'bio')
    search_fields = ('user__username', 'user__email', 'location')
    list_filter = ('user_type', 'location')


@admin.register(Resume)
class ResumeAdmin(admin.ModelAdmin):
    list_display = ('user_profile', 'resume_name')
    

@admin.register(SocialLink)
class SocialLinkAdmin(admin.ModelAdmin):
    list_display = ('user_profile', 'linkedin', 'github', 'twitter', 'facebook', 'instagram', 'personal_website')
