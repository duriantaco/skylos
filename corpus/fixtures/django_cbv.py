from django.http import HttpResponse
from django.views import View


class HomeView(View):
    def get(self, request):
        return HttpResponse("ok")


class PageFormatter:
    def format_page(self):
        return "preview"


class PageRenderer:
    def format_page(self):
        return "preview"


PageRenderer()
