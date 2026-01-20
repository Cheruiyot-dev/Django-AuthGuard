# accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('verify-email/<uuid:token>/', views.verify_email, name='verify_email'),
    path('profile/', views.user_profile, name='profile'),
    path('assign-role/', views.assign_role, name='assign_role'),
    path('change-password/', views.change_password, name='change_password'),
    path('reset-password/', views.reset_password, name='reset_password'),
]

