from marshmallow import Schema, validates_schema


class UserSchema(Schema):
    @validates_schema
    def validate_schema(self, data, **kwargs):
        return None
