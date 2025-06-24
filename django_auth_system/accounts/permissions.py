# accounts/permissions.py
from rest_framework import permissions
from .models import UserRole

class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.owner == request.user

class HasRolePermission(permissions.BasePermission):
    required_roles = []
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        user_roles = UserRole.objects.filter(user=request.user).values_list('role__name', flat=True)
        return any(role in self.required_roles for role in user_roles)

class IsAdminOrOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        return hasattr(obj, 'owner') and obj.owner == request.user