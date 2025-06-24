# accounts/views.py
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from .serializers import UserRegistrationSerializer
from django_ratelimit.decorators import ratelimit

from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import timedelta
import uuid

from .models import Role, UserRole
from .permissions import HasRolePermission

User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='5/m', method='POST')
def register_user(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.password = make_password(serializer.validated_data['password'])
        user.verification_token = uuid.uuid4()  # This will be stored as UUID in the database
        user.save()
        # Send verification email
        send_verification_email(user)
        return Response({
            'message': 'User registered successfully. Please check your email for verification.',
            'user_id': user.id
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def send_verification_email(user):
    verification_url = f"http://localhost:8000/api/auth/verify-email/{str(user.verification_token)}/"
    send_mail(
        'Verify your email',
        f'Click here to verify: {verification_url}',
        'noreply@yourapp.com',
        [user.email],
        fail_silently=False,
    )


# Login view

@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='5/m', method='POST')
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response({'error': 'Email and password required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        
        # Check if account is locked
        if user.is_account_locked():
            return Response({'error': 'Account temporarily locked due to failed login attempts'}, 
                          status=status.HTTP_423_LOCKED)
        
        # Authenticate user
        authenticated_user = authenticate(request, username=email, password=password)
        
        if authenticated_user:
            if not authenticated_user.is_verified:
                return Response({'error': 'Please verify your email first'}, 
                              status=status.HTTP_403_FORBIDDEN)
            
            # Reset failed attempts and update login info
            user.reset_failed_attempts()
            user.last_login_ip = get_client_ip(request)
            user.save(update_fields=['last_login_ip'])
            
            # Generate tokens
            refresh = RefreshToken.for_user(authenticated_user)
            
            # Create session record
            create_user_session(authenticated_user, request)
            
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': {
                    'id': authenticated_user.id,
                    'email': authenticated_user.email,
                    'username': authenticated_user.username,
                }
            }, status=status.HTTP_200_OK)
        else:
            # Handle failed login
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.account_locked_until = timezone.now() + timedelta(minutes=30)
            user.save(update_fields=['failed_login_attempts', 'account_locked_until'])
            
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    except User.DoesNotExist:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def create_user_session(user, request):
    from .models import UserSession
    UserSession.objects.create(
        user=user,
        session_key=request.session.session_key or 'api_session',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        expires_at=timezone.now() + timedelta(days=7)
    )


# Role Management View
class AdminRolePermission(HasRolePermission):
    required_roles = ['admin', 'super_admin']

@api_view(['POST'])
@permission_classes([AdminRolePermission])
def assign_role(request):
    user_id = request.data.get('user_id')
    role_name = request.data.get('role_name')
    
    try:
        user = User.objects.get(id=user_id)
        role = Role.objects.get(name=role_name)
        
        user_role, created = UserRole.objects.get_or_create(
            user=user,
            role=role,
            defaults={'assigned_by': request.user}
        )
        
        if created:
            return Response({'message': f'Role {role_name} assigned to user {user.email}'})
        else:
            return Response({'message': 'User already has this role'})
    
    except (User.DoesNotExist, Role.DoesNotExist) as e:
        return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)

# Logout View
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        # Blacklist the refresh token
        token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
        RefreshToken(token).blacklist()
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    try:
       
        user = User.objects.get(verification_token=token)
        
        if user.is_verified:
            return Response({'message': 'Email already verified.'}, status=status.HTTP_200_OK)
        
        user.is_verified = True
        user.verification_token = None  # Clear the token after verification
        user.save(update_fields=['is_verified', 'verification_token'])
        
        return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({'error': 'Invalid or expired verification token.'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': 'An error occurred during verification.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    return Response({
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'is_verified': getattr(user, 'is_verified', None),
      
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')

    if not old_password or not new_password:
        return Response({'error': 'Old and new passwords are required.'}, status=status.HTTP_400_BAD_REQUEST)

    if not user.check_password(old_password):
        return Response({'error': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()
    return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        user = User.objects.get(email=email)
        # Generate a reset token
        reset_token = str(uuid.uuid4())
        user.reset_token = reset_token
        user.save(update_fields=['reset_token'])
        # Send reset email
        reset_url = f"http://localhost:8000/api/reset-password-confirm/{reset_token}/"
        send_mail(
            'Password Reset',
            f'Click here to reset your password: {reset_url}',
            'noreply@yourapp.com',
            [user.email],
            fail_silently=False,
        )
        return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)