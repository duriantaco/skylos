from django.contrib import admin


@admin.register(object)
class UserAdmin(admin.ModelAdmin):
    pass


class AdminDraft:
    pass
