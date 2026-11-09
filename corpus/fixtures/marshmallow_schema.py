from marshmallow import Schema, post_load


class UserSchema(Schema):
    @post_load
    def make_user(self, data, **kwargs):
        return data


class PayloadParser:
    def parse_item(self, data):
        return data


class ItemLoader:
    def parse_item(self, data):
        return data


ItemLoader()
