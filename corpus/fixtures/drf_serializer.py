from rest_framework import serializers


class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value
