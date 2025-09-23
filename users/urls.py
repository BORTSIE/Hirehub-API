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
    path('get_user/', views.get_user),
    path('forgot_password/', views.forgot_password),
    path('reset_password/', views.reset_password),
    path('change_password/', views.change_password),
    path('activate_account/', views.activate_account),
    path('jobs/', views.list_jobs),
    path('jobs/create/', views.create_job),
    path('jobs/<uuid:pk>/', views.retrieve_job),
    path('jobs/<uuid:pk>/update/', views.update_job),
    path('jobs/<uuid:pk>/delete/', views.delete_job),
    path('resend_activation_email/<str:email>/', views.resend_activation_email),
    
    
    ]