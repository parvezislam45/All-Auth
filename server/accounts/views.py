from django.shortcuts import render
from .serializers import RegisterSerializer, LoginSerializer,LogoutSerializer,passwordResetSerializer,UserSerializer
from .models import User
from rest_framework import generics, status,permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes
from django.views.generic import DetailView
from django.shortcuts import redirect
from django.http import Http404
from django.contrib import messages
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        serializer.is_valid(raise_exception=True)
        
        # Save the new user
        serializer.save()
        user = User.objects.get(username=serializer.validated_data['username'])
        
        # Generate JWT tokens (automatically log the user in)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response_data = {
            'user': serializer.data,
            'refresh_token': str(refresh),
            'access_token': access_token
        }
        
        return Response(response_data, status=status.HTTP_201_CREATED)


class LoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Retrieve validated data
        user_data = serializer.validated_data

        # Response with user data and tokens
        response_data = {
            'username': user_data['username'],
            'email': user_data['email'],
            'tokens': user_data['tokens']
        }

        return Response(response_data, status=status.HTTP_200_OK)
        
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile_data = {
            'email': user.email,
            'role': user.role,
        }
        return Response(profile_data, status=status.HTTP_200_OK)    
        
class LogoutApiView(generics.GenericAPIView):
    authentication_classes = []  
    permission_classes = [AllowAny] 
    serializer_class = LogoutSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save() 
        return Response({'detail': 'Successfully Logged Out'}, status=status.HTTP_200_OK)
    
class PasswordResetOtpEmailView(generics.GenericAPIView):
    serializer_class = passwordResetSerializer  
    
    def post(self, request, *args, **kwargs): 
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        data = serializer.save() 
        
        # Construct the reset password confirmation link
        confirmation_url_password_reset = f'http://localhost:8000/reset-password-confirm/?email={email}&otp={data["otp"]}'
        subject = 'Password Reset OTP and Confirmation Link'
        message = f'Use this OTP to Reset your Password: {data["otp"]}\n\nFollow this link to reset your password: {confirmation_url_password_reset}'
        from_email = 'webmaster@example.com'
        recipient_list = [email]
    
        send_mail(subject, message, from_email, recipient_list)
        
        return Response({'message': 'Password Reset OTP and Confirmation Link sent Successfully'}, status=status.HTTP_200_OK)


class PasswordResetConfirmationView(DetailView):
    model = User
    template_name = 'password_reset_confirmation.html'
    context_object_name = 'user'
    
    def get_object(self, queryset=None):
        email = self.request.GET.get('email')
        otp = self.request.GET.get('otp')
        
        if not email or not otp:
            raise Http404('Invalid URL')  
       
        user = User.objects.filter(email=email, login_token=otp).first()
        if user is None:
            raise Http404('Invalid OTP') 
        return user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        new_password = request.POST.get('password')
        
        if new_password:
            user.set_password(new_password)  
            
            messages.success(request, 'Password reset successfully')  
            return redirect('accounts:login') 
        else:
            messages.error(request, 'Password cannot be empty') 
            return redirect(request.path) 
        
        
    
    
