from rest_framework import serializers
from .models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm', 'phone_number')

    def validate(self, attrs):
        """
        Validates that the 'password' and 'password_confirm' fields in the input attributes match.

        Args:
            attrs (dict): The input data containing 'password' and 'password_confirm' fields.

        Raises:
            serializers.ValidationError: If the passwords do not match.

        Returns:
            dict: The validated attributes if passwords match.
        """
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs
    

    def create(self, validated_data):
        """
        Creates and saves a new User instance with the provided validated data.

        Removes the 'password_confirm' field from the validated data, sets the user's password securely,
        and saves the user to the database.

        Args:
            validated_data (dict): The validated data containing user information.

        Returns:
            User: The newly created User instance.
        """
        validated_data.pop('password_confirm')
        user = User(**validated_data)
        print("user is:", user)
        user.set_password(validated_data['password'])
        user.save()
        print(f"User {user.email} created successfully.")
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'phone_number', 'is_verified', 'created_at')
        read_only_fields = ('id', 'is_verified', 'created_at')