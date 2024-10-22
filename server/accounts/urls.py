from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView  # Import TokenVerifyView

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginApiView.as_view(), name='login'),
    path('profile/', views.ProfileView.as_view(), name='profile'), 
    path('logout/', views.LogoutApiView.as_view(), name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),  # Add token verify URL
    path('reset-password-email/', views.PasswordResetOtpEmailView.as_view(), name='reset-password-email'),
    path('reset-password-confirmation/', views.PasswordResetConfirmationView.as_view(), name='reset-password-confirmed'),
]
