from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.utils.crypto import get_random_string




class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100)
    is_superuser = serializers.BooleanField(default=False)
    is_staff = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'is_superuser', 'is_staff', 'role')  # Add 'role'

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError("The username should only contain alphanumeric characters.")
        return attrs

    def create(self, validated_data):
        # Assign default role 'user' if not explicitly provided
        validated_data['role'] = 'user'
        
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            full_name=validated_data.get('full_name', ''),
            is_superuser=validated_data['is_superuser'],
            is_staff=validated_data['is_staff'],
            role=validated_data['role']  # Add 'role' in user creation
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    
    
class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=20, min_length=6, write_only=True)
    username = serializers.CharField(max_length=200, min_length=4)
    tokens = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['username', 'password', 'tokens']

    def get_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token)
        }

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')

        user = auth.authenticate(username=username, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, please try again.')

        return {
            'username': user.username,
            'email': user.email,
            'tokens': self.get_tokens(user)
        }
        
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']       
        
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError as e:
            raise serializers.ValidationError(str(e))
        
        
class passwordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    def validate_email(self, value):
        user = User.objects.filter(email=value).first()
        if user is None:
            raise serializers.ValidationError('no user found with this email')
        return value
    
    def save(self):
        email = self.validate_data['email']
        user = User.objects.get(email=email)
        otp = get_random_string(length=6, allowed_chars = '1234567890')
        user.login_token = otp
        user.save()
        return {'user': user, 'otp':otp}
        