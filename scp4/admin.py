from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from .models import ScanResult, Vulnerability, UserActivityLog 

admin.site.site_header = "CodeScan Admin System"
admin.site.site_title = "CodeScan Admin"
admin.site.index_title = "Manager System"

class CustomUserAdmin(UserAdmin):
    def get_queryset(self, request):
        qs = super().get_queryset(request)
    
        if not request.user.is_superuser:
            return qs.exclude(is_superuser=True)
        return qs
    
@admin.register(UserActivityLog)
class UserActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'event_type', 'timestamp')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('user__username',)

    

admin.site.register(ScanResult)
admin.site.register(Vulnerability)
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


