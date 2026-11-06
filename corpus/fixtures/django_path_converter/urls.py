from django.urls import path, register_converter  # skylos: ignore[SKY-D223] corpus fixture dependency


class FourDigitYearConverter:
    regex = "[0-9]{4}"

    def to_python(self, value):
        return int(value)

    def to_url(self, value):
        return "%04d" % value


register_converter(FourDigitYearConverter, "yyyy")
urlpatterns = []


class DateCodec:
    date_pattern = "[0-9]{2}"

    def decode_date(self, value):
        return int(value)

    def encode_date(self, value):
        return "%02d" % value


class DateParser:
    def decode_date(self, value):
        return int(value)

    def encode_date(self, value):
        return "%02d" % value


DateParser()
