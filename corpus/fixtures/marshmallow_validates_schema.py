from marshmallow import Schema, validates_schema


class UserSchema(Schema):
    @validates_schema
    def validate_schema(self, data, **kwargs):
        return None


class PayloadValidator:
    pass


def validate_record(data):
    return data
