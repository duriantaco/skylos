from marshmallow import Schema, post_load


class UserSchema(Schema):
    @post_load
    def make_user(self, data, **kwargs):
        return data
