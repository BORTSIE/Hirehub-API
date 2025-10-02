from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path("register/", views.register),
    path("login/", views.login),
    path("refresh/", views.customTokenRefreshView.as_view()),
    path("logout/", views.logout),
    path("activate_account/", views.activate_account),
    path("forgot_password/", views.forgot_password),
    path("reset_password/", views.reset_password),
    path("change_password/", views.change_password),
    path("resend_activation_email/<str:email>/", views.resend_activation_email),
    path("get_authentication/", views.get_authentication),
 
    # Profile
     path("profile/", views.get_user),
    path("profile_save/", views.save_user_profile, name="save_user_profile"),

    #Resume
    path("resume_save/", views.save_resume, name="save_resume"),

    # Social Links
    path("social_links/", views.get_socail_links, name="get_social_links"),
    path("social_links/save/", views.save_social_links, name="save_social_links"),

    # Jobs
    path("jobs/list/", views.list_jobs),
    path("jobs/create/", views.create_job),#  EM only
    path("jobs/retrieve/<uuid:pk>/", views.retrieve_job),
    path("jobs/<uuid:pk>/update/", views.update_job),
    path("jobs/<uuid:pk>/delete/", views.delete_job),

    # Companies
    path("companies/", views.list_companies),
    path("create_company/", views.create_company), #EM only
    path("get_company/<uuid:id>/", views.get_company),

    # Applications
    path("apply_job/<uuid:job_id>/", views.apply_to_job), #JS only
    path("applications_list/<uuid:job_id>/", views.list_applications),
    path("application_update/<uuid:application_id>/", views.update_application_status),

    # Saved Jobs
    path("save_job/<uuid:job_id>/", views.save_job),
    path("saved_jobs_list/", views.list_saved_jobs),
    path("delete_saved_job/<uuid:saved_job_id>/", views.delete_saved_job),  

    # Notifications
    path("notifications/", views.list_notifications, name="list_notifications"),
    path("notifications/<int:notification_id>/read/", views.mark_notification_as_read, name="mark_notification_as_read"),

    # Conversations
    path("conversations/", views.list_conversations, name="list_conversations"),
    path("conversations/<int:conversation_id>/messages/", views.retrieve_messages, name="retrieve_messages"),
    path("conversations/<int:conversation_id>/messages/send/", views.send_message, name="send_message"),
    path("conversations/send/", views.send_message, name="start_conversation"),  # when no conversation_id is given

    # Mark message as read
    path("messages/<int:message_id>/read/", views.mark_message_as_read, name="mark_message_as_read"),

    # Dashboard Endpoints
    path("dashboard/employer/", views.employer_dashboard),
    path("dashboard/jobseeker/", views.jobseeker_dashboard),


] # http://127.0.0.1:8000/    http://127.0.0.1:8000/api


""
#register/
{
  "fullname": "Papa Bentil",
  "username": "Paapa",
  "user_type": "JS", 
  "email": "paapabentil22@gmail.com",
  "password": "StrongPassword123",
  "password2": "StrongPassword123"
}
#activate_account/
{
  "uid": "NDA",
  "token": "cwqd75-ce87f5384f3cf69f4ae1e7554c11edee"
}

#resend_activation_email/

#login/
{
   "email": "nanayawmensah6404@gmail.com",
  "password": "StrongPassword123"
}

#profile_save/
{
  "full_name": "Nana Yaw",
  "bio": "Software developer with 5 years of experience in backend systems.",
  "location": "Takoradi, Ghana",
  "birth_date": "1995-07-15",
  "experience": "5 years at XYZ Tech as Backend Developer",
  "education": "BSc Computer Science, University of Ghana",
  "nationality": "Ghanaian",
  "gender": "Male"
}

#profile/

#forgot_password/
{
    "email":""
}

#reset_password/
{
  "uidb64": "Mg", 
  "token": "5n2-0b2f9f97e6a1c0c2c6c",
  "new_password": "MyNewSecurePassword123",
  "new_password2": "MyNewSecurePassword123"
}

#change_password/
{
  "old_password": "StrongPassword123",
  "new_password": "MyNewSecurePassword123",
  "new_password2": "MyNewSecurePassword123"
}






""