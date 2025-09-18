from django.urls import path
from . import views

urlpatterns = [
    path('login/',views.login), 
    path('register/',views.register),
    path('refresh/', views.customTokenRefreshView.as_view()),
    # path('profile/',views.get_profile), 
    # path('resume/',views.get_resume),
    path('social-links/',views.get_socail_links),
    path("profile_save/", views.save_user_profile),
    path("resume_save/", views.save_resume),
    path("social_save/", views.save_social_links),
    
    ]