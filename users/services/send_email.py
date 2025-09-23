from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes



# Send account activation email
def send_activation_email(user):
        full_name = f"{user.first_name} {user.last_name}".strip() or user.username
        email = user.email
       
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = f"http://localhost:5173/auth/activate?uid={uidb64}&token={token}/"   

        send_mail(
            subject="Activate your HireHub account",    
            message=f"{full_name}, please click the link to activate your account: {activation_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
