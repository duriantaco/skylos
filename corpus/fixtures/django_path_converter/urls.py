from django.urls import path, register_converter  # skylos: ignore[SKY-D223] corpus fixture dependency


class FourDigitYearConverter:
    regex = "[0-9]{4}"

    def to_python(self, value):
        return int(value)

    def to_url(self, value):
        return "%04d" % value


register_converter(FourDigitYearConverter, "yyyy")
urlpatterns = []
