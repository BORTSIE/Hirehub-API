from django.contrib import admin
from .models import (
    UserProfile,
    Resume,
    SocialLink,
    Company,
    Job,
    Salary,
    ContactInfo,
    FoundingInfo,
    SocialLinks,
    JobApplication,
)


# ✅ User Profile
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user", "user_type", "full_name", "location",
        "birth_date", "nationality", "experience", "education", "gender"
    )
    search_fields = ("user__username", "user__email", "location")
    list_filter = ("user_type", "location")


# ✅ Resume
@admin.register(Resume)
class ResumeAdmin(admin.ModelAdmin):
    list_display = ("user_profile", "resume_name")
    search_fields = ("user_profile__user__username", "user_profile__user__email", "resume_name")
    list_filter = ("user_profile__user__is_active",)


# ✅ Social Link (per user)
@admin.register(SocialLink)
class SocialLinkAdmin(admin.ModelAdmin):
    list_display = ("user_profile", "linkedin", "github", "twitter", "facebook", "instagram", "personal_website")
    search_fields = ("user_profile__user__username", "user_profile__user__email")
    list_filter = ("user_profile__user__is_active",)


# ✅ Company
@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ("name", "about_us")
    search_fields = ("name",)
    list_filter = ("founding_info__industry_type",)


# ✅ Job
@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ("title", "company", "type", "level", "posted_at", "expires_at", "is_expired")
    search_fields = ("title", "description", "company__name")
    list_filter = ("type", "level", "posted_at", "is_expired")


# ✅ Salary
@admin.register(Salary)
class SalaryAdmin(admin.ModelAdmin):
    list_display = ("min", "max")
    search_fields = ("min", "max")


# ✅ Contact Info
@admin.register(ContactInfo)
class ContactInfoAdmin(admin.ModelAdmin):
    list_display = ("email", "phone", "map_location")
    search_fields = ("email", "phone", "map_location")


# ✅ Founding Info
@admin.register(FoundingInfo)
class FoundingInfoAdmin(admin.ModelAdmin):
    list_display = ("org_type", "industry_type", "team_size", "year_established")
    search_fields = ("org_type", "industry_type")


# ✅ Company Social Links
@admin.register(SocialLinks)
class SocialLinksAdmin(admin.ModelAdmin):
    list_display = ("facebook", "twitter", "linkedin", "instagram")


# ✅ Job Applications
@admin.register(JobApplication)
class JobApplicationAdmin(admin.ModelAdmin):
    list_display = ("job", "applicant", "status", "applied_at")
    search_fields = ("job__title", "applicant__user__username", "applicant__user__email")
    list_filter = ("status", "applied_at")
