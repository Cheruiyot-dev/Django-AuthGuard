# Django AuthGuard

A robust authentication and authorization system for Django REST Framework, featuring email verification, JWT authentication, role-based access control, account lockout, and more.

## Features
- User registration with email verification
- JWT authentication (access/refresh tokens)
- Role-based access control (RBAC)
- Account lockout after multiple failed login attempts
- Password reset via email
- User session tracking
- Admin role assignment

## Requirements
- Python 3.10+
- Django 5.x
- Django REST Framework
- djangorestframework-simplejwt
- Other dependencies in `requirements.txt`

## Setup
1. Clone the repository:
   ```sh
   git clone https://github.com/Cheruiyot-dev/Django-AuthGuard.git
   
   cd Django-AuthGuard
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Apply migrations:
   ```sh
   python manage.py makemigrations
   python manage.py migrate
   ```
4. Create a superuser (for admin access):
   ```sh
   python manage.py createsuperuser
   ```
5. Run the development server:
   ```sh
   python manage.py runserver
   ```

## API Endpoints

### Authentication & User
- **POST** `/api/auth/register/`  
  Register a new user. Requires: `email`, `username`, `password`.

- **POST** `/api/auth/login/`  
  Log in a user. Requires: `email`, `password`. Returns JWT tokens.

- **POST** `/api/auth/logout/`  
  Log out the current user (JWT blacklist).

- **GET** `/api/auth/verify-email/<uuid:token>/`  
  Verify a user's email using a verification token sent via email.

- **GET** `/api/auth/profile/`  
  Get the authenticated user's profile. Requires authentication.

- **POST** `/api/auth/assign-role/`  
  Assign a role to a user (admin only). Requires: `user_id`, `role_name`.

- **POST** `/api/auth/change-password/`  
  Change the authenticated user's password. Requires: `old_password`, `new_password`.

- **POST** `/api/auth/reset-password/`  
  Send a password reset link to the user's email. Requires: `email`.

## Models
- **User**: Custom user model with email as username, verification, lockout, and session fields.
- **Role**: Defines user roles for RBAC.
- **UserRole**: Associates users with roles.
- **UserSession**: Tracks user sessions.
- **RefreshToken**: JWT refresh tokens.

## Security
- Email verification required before login
- Account lockout after 5 failed login attempts (30 min lock)
- JWT-based authentication
- Role-based permissions for admin actions

## Customization
- Add more roles in the admin panel or via migration
- Extend user fields as needed in `accounts/models.py`




