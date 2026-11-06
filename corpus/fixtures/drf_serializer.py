from rest_framework import serializers


class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value


class ContactRecord:
    address = "office"

    def normalize_address(self, value):
        return value


class ContactFormatter:
    def normalize_address(self, value):
        return value


ContactFormatter()
