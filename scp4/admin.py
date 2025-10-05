from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Count, Sum
from django.utils import timezone
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.contrib import messages
from .models import ScanResult, Vulnerability, UserProfile, VulnerabilityKnowledge

# ✅ เพิ่มการจัดการ User model อย่างปลอดภัย
admin.site.unregister(User)

class SecureUserAdmin(BaseUserAdmin):
    """
    User Admin ที่ปลอดภัย - ป้องกัน staff ลบ superuser และเปลี่ยนสิทธิ์
    """
    
    def has_delete_permission(self, request, obj=None):
        """กำหนดสิทธิ์การลบอย่างเข้มงวด"""
        if request.user.is_superuser:
            if obj and obj.id == request.user.id:
                return False
            return True
        
        if request.user.is_staff:
            if obj:
                if obj.is_superuser or obj.is_staff:
                    return False
                return True
            else:
                return True
        
        return False
    
    def delete_model(self, request, obj):
        """ตรวจสอบก่อนลบ"""
        if not self.has_delete_permission(request, obj):
            messages.error(request, f"คุณไม่มีสิทธิ์ลบผู้ใช้ {obj.username}")
            raise PermissionDenied("คุณไม่มีสิทธิ์ลบผู้ใช้นี้")
        
        messages.success(request, f"ลบผู้ใช้ {obj.username} เรียบร้อยแล้ว")
        super().delete_model(request, obj)
    
    def delete_queryset(self, request, queryset):
        """ตรวจสอบการลบหลายคนพร้อมกัน"""
        forbidden_users = []
        for obj in queryset:
            if not self.has_delete_permission(request, obj):
                forbidden_users.append(obj.username)
        
        if forbidden_users:
            messages.error(request, f"คุณไม่มีสิทธิ์ลบผู้ใช้: {', '.join(forbidden_users)}")
            raise PermissionDenied("คุณไม่มีสิทธิ์ลบผู้ใช้บางคน")
        
        super().delete_queryset(request, queryset)
    
    def get_readonly_fields(self, request, obj=None):
        """กำหนด field ที่ staff แก้ไขไม่ได้"""
        readonly_fields = list(super().get_readonly_fields(request, obj))
        
        if request.user.is_staff and not request.user.is_superuser:
            if obj:
                if obj.id == request.user.id:
                    readonly_fields.extend(['is_superuser', 'is_staff', 'user_permissions', 'groups'])
                elif obj.is_superuser:
                    readonly_fields.extend(['is_superuser', 'is_staff', 'user_permissions', 'groups'])
                elif obj.is_staff:
                    readonly_fields.extend(['is_superuser', 'is_staff', 'user_permissions', 'groups'])
                else:
                    readonly_fields.extend(['is_superuser', 'is_staff', 'user_permissions', 'groups'])
        
        return readonly_fields
    
    def save_model(self, request, obj, form, change):
        """เพิ่มการตรวจสอบก่อนบันทึก"""
        if request.user.is_superuser:
            super().save_model(request, obj, form, change)
            return
        
        if request.user.is_staff:
            if obj.id == request.user.id:
                if obj.is_superuser or not obj.is_staff:
                    messages.error(request, "คุณไม่สามารถเปลี่ยนสิทธิ์ของตัวเองได้")
                    raise PermissionDenied("ไม่สามารถเปลี่ยนสิทธิ์ตัวเองได้")
            else:
                if obj.is_superuser or obj.is_staff:
                    if change:
                        original_user = User.objects.get(pk=obj.pk)
                        if (not original_user.is_staff and obj.is_staff) or \
                           (not original_user.is_superuser and obj.is_superuser):
                            messages.error(request, "คุณไม่สามารถให้สิทธิ์ admin แก่ผู้ใช้คนอื่นได้")
                            raise PermissionDenied("ไม่สามารถให้สิทธิ์ admin แก่ผู้ใช้คนอื่นได้")
                    else:
                        if obj.is_staff or obj.is_superuser:
                            messages.error(request, "คุณไม่สามารถสร้างผู้ใช้ที่มีสิทธิ์ admin ได้")
                            raise PermissionDenied("ไม่สามารถสร้างผู้ใช้ที่มีสิทธิ์ admin ได้")
        
        super().save_model(request, obj, form, change)
    
    def has_change_permission(self, request, obj=None):
        """กำหนดสิทธิ์การแก้ไข"""
        if request.user.is_superuser:
            return True
        
        if request.user.is_staff and obj and obj.is_superuser:
            return False
        
        return super().has_change_permission(request, obj)

admin.site.register(User, SecureUserAdmin)


@admin.register(VulnerabilityKnowledge)
class VulnerabilityKnowledgeAdmin(admin.ModelAdmin):
    """จัดการฐานความรู้ช่องโหว่ (Knowledge Base สำหรับ RAG)"""
    
    list_display = [
        'name',
        'cwe_id',
        'severity_badge',
        'owasp_category',
        'is_active',
        'has_examples',
        'created_at'
    ]
    
    list_filter = [
        'severity',
        'is_active',
        'owasp_category',
        'created_at'
    ]
    
    search_fields = [
        'name',
        'cwe_id',
        'description',
        'keywords',
        'owasp_category'
    ]
    
    list_editable = ['is_active']
    
    readonly_fields = ['created_at', 'updated_at', 'keywords_display']
    
    ordering = ['name']
    
    fieldsets = (
        ('ข้อมูลหลัก', {
            'fields': (
                'name',
                'cwe_id',
                'owasp_category',
                'severity',
                'is_active'
            )
        }),
        ('คำอธิบาย', {
            'fields': (
                'description',
                'impact',
                'remediation'
            )
        }),
        ('ตัวอย่างโค้ด', {
            'fields': (
                'vulnerable_code_example',
                'secure_code_example'
            ),
            'classes': ('collapse',)
        }),
        ('การค้นหา (RAG)', {
            'fields': (
                'keywords',
                'keywords_display'
            ),
            'description': 'คำสำคัญสำหรับระบบ RAG ค้นหา (คั่นด้วยเครื่องหมายจุลภาค)'
        }),
        ('ข้อมูลอ้างอิง', {
            'fields': ('reference_url',),
            'classes': ('collapse',)
        }),
        ('ข้อมูลระบบ', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def severity_badge(self, obj):
        """Badge แสดง severity"""
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#17a2b8',
            'Informational': '#6c757d'
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold;">{}</span>',
            color,
            obj.severity
        )
    severity_badge.short_description = 'ระดับความรุนแรง'
    severity_badge.admin_order_field = 'severity'
    
    def has_examples(self, obj):
        """แสดงว่ามีตัวอย่างโค้ดหรือไม่"""
        has_vuln = bool(obj.vulnerable_code_example)
        has_secure = bool(obj.secure_code_example)
        
        if has_vuln and has_secure:
            return format_html('<span style="color: green;">✓ ครบ</span>')
        elif has_vuln or has_secure:
            return format_html('<span style="color: orange;">⚠ บางส่วน</span>')
        else:
            return format_html('<span style="color: red;">✗ ไม่มี</span>')
    has_examples.short_description = 'ตัวอย่างโค้ด'
    
    def keywords_display(self, obj):
        """แสดง keywords เป็น badges"""
        if not obj.keywords:
            return "ไม่มีคำสำคัญ"
        
        keywords_list = obj.keywords_list
        badges = []
        for keyword in keywords_list[:10]:  # แสดงแค่ 10 คำแรก
            badges.append(
                f'<span style="background: #e3f2fd; color: #1976d2; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin: 2px;">{keyword}</span>'
            )
        
        if len(keywords_list) > 10:
            badges.append(f'<span style="color: #666;">...และอีก {len(keywords_list) - 10} คำ</span>')
        
        return format_html(' '.join(badges))
    keywords_display.short_description = 'คำสำคัญที่ใช้ค้นหา (RAG)'
    
    actions = ['activate_knowledge', 'deactivate_knowledge', 'duplicate_knowledge']
    
    def activate_knowledge(self, request, queryset):
        """เปิดใช้งานความรู้"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'เปิดใช้งาน {updated} รายการ')
    activate_knowledge.short_description = 'เปิดใช้งานที่เลือก'
    
    def deactivate_knowledge(self, request, queryset):
        """ปิดใช้งานความรู้"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'ปิดใช้งาน {updated} รายการ')
    deactivate_knowledge.short_description = 'ปิดใช้งานที่เลือก'
    
    def duplicate_knowledge(self, request, queryset):
        """ทำซ้ำความรู้"""
        count = 0
        for obj in queryset:
            obj.pk = None
            obj.name = f"{obj.name} (Copy)"
            obj.save()
            count += 1
        self.message_user(request, f'ทำซ้ำ {count} รายการ')
    duplicate_knowledge.short_description = 'ทำซ้ำที่เลือก'


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = [
        'user', 
        'total_scans_count', 
        'last_scan_date', 
        'email_notifications',
        'preferred_language',
        'created_at'
    ]
    list_filter = [
        'email_notifications',
        'preferred_language', 
        'created_at',
        'last_scan_date'
    ]
    search_fields = ['user__username', 'user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('ข้อมูลผู้ใช้', {
            'fields': ('user',)
        }),
        ('การตั้งค่า', {
            'fields': ('email_notifications', 'preferred_language')
        }),
        ('สถิติ', {
            'fields': ('total_scans_count', 'last_scan_date'),
            'classes': ('collapse',)
        }),
        ('ข้อมูลระบบ', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0
    fields = ['name', 'severity', 'description', 'remediation']
    readonly_fields = ['created_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).order_by('severity')


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'user_link', 
        'scanned_at',
        'ai_model_used',
        'rag_indicator',
        'vulnerability_summary',
        'risk_level_badge',
        'total_vulnerabilities'
    ]
    list_filter = [
        'scanned_at',
        'ai_model_used',
        'total_vulnerabilities',
        'critical_severity_count',
        'high_severity_count',
        'knowledge_base_count',
        'user'
    ]
    search_fields = [
        'user__username', 
        'user__email',
        'scanned_code',
        'analysis_result_raw'
    ]
    readonly_fields = [
        'scanned_at', 
        'vulnerability_counts_display',
        'code_preview',
        'rag_info_display'
    ]
    date_hierarchy = 'scanned_at'
    inlines = [VulnerabilityInline]
    
    fieldsets = (
        ('ข้อมูลการสแกน', {
            'fields': ('user', 'scanned_at', 'ai_model_used')
        }),
        ('ข้อมูล RAG', {
            'fields': ('rag_info_display', 'knowledge_base_count', 'rag_context_used'),
            'classes': ('collapse',)
        }),
        ('โค้ดที่สแกน', {
            'fields': ('code_preview', 'scanned_code'),
            'classes': ('collapse',)
        }),
        ('ผลลัพธ์จาก AI', {
            'fields': ('analysis_result_raw',),
            'classes': ('collapse',)
        }),
        ('สถิติช่องโหว่', {
            'fields': ('vulnerability_counts_display', 'total_vulnerabilities'),
        }),
        ('จำนวนช่องโหว่แต่ละระดับ', {
            'fields': (
                'critical_severity_count',
                'high_severity_count', 
                'medium_severity_count',
                'low_severity_count',
                'info_severity_count'
            ),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user').prefetch_related('vulnerabilities')

    def rag_indicator(self, obj):
        """แสดง indicator ว่าใช้ RAG หรือไม่"""
        if obj.knowledge_base_count > 0:
            return format_html(
                '<span style="background: #4caf50; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">RAG: {}</span>',
                obj.knowledge_base_count
            )
        else:
            return format_html('<span style="color: #999;">ไม่ใช้ RAG</span>')
    rag_indicator.short_description = 'RAG'
    rag_indicator.admin_order_field = 'knowledge_base_count'
    
    def rag_info_display(self, obj):
        """แสดงข้อมูล RAG แบบละเอียด"""
        if obj.knowledge_base_count == 0:
            return format_html('<p style="color: #999;">ไม่มีการใช้ข้อมูลจาก Knowledge Base</p>')
        
        return format_html(
            '<div style="background: #f0f8ff; padding: 10px; border-radius: 4px; border-left: 3px solid #4caf50;">'
            '<strong>ใช้ข้อมูลจาก Knowledge Base: {} รายการ</strong><br>'
            '<small style="color: #666;">ระบบดึงข้อมูลช่องโหว่ที่เกี่ยวข้องมาช่วยในการวิเคราะห์</small>'
            '</div>',
            obj.knowledge_base_count
        )
    rag_info_display.short_description = 'ข้อมูล RAG'

    def user_link(self, obj):
        """ลิงก์ไปยังผู้ใช้"""
        return format_html(
            '<a href="/admin/auth/user/{}/change/">{}</a>',
            obj.user.id,
            obj.user.username
        )
    user_link.short_description = 'ผู้ใช้'
    user_link.admin_order_field = 'user__username'

    def vulnerability_summary(self, obj):
        """สรุปช่องโหว่"""
        if obj.total_vulnerabilities == 0:
            return format_html('<span style="color: green;">ไม่พบช่องโหว่</span>')
        
        parts = []
        if obj.critical_severity_count > 0:
            parts.append(f'<span style="color: #dc3545;">Critical: {obj.critical_severity_count}</span>')
        if obj.high_severity_count > 0:
            parts.append(f'<span style="color: #fd7e14;">High: {obj.high_severity_count}</span>')
        if obj.medium_severity_count > 0:
            parts.append(f'<span style="color: #ffc107;">Medium: {obj.medium_severity_count}</span>')
        if obj.low_severity_count > 0:
            parts.append(f'<span style="color: #17a2b8;">Low: {obj.low_severity_count}</span>')
        
        return format_html(' | '.join(parts))
    vulnerability_summary.short_description = 'สรุปช่องโหว่'

    def risk_level_badge(self, obj):
        """Badge แสดงระดับความเสี่ยง"""
        risk = obj.risk_level
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#17a2b8',
            'Safe': '#28a745'
        }
        color = colors.get(risk, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px;">{}</span>',
            color,
            risk
        )
    risk_level_badge.short_description = 'ระดับความเสี่ยง'

    def code_preview(self, obj):
        """แสดงตัวอย่างโค้ด"""
        if not obj.scanned_code:
            return "ไม่มีโค้ด"
        
        preview = obj.scanned_code[:200]
        if len(obj.scanned_code) > 200:
            preview += "..."
            
        return format_html(
            '<pre style="background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px; max-height: 150px; overflow-y: auto;">{}</pre>',
            preview
        )
    code_preview.short_description = 'ตัวอย่างโค้ด'

    def vulnerability_counts_display(self, obj):
        """แสดงจำนวนช่องโหว่แบบสวยงาม"""
        return format_html(
            '''
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; max-width: 300px;">
                <div style="text-align: center; padding: 5px; background: #dc3545; color: white; border-radius: 4px;">
                    <div style="font-weight: bold;">{}</div>
                    <div style="font-size: 11px;">Critical</div>
                </div>
                <div style="text-align: center; padding: 5px; background: #fd7e14; color: white; border-radius: 4px;">
                    <div style="font-weight: bold;">{}</div>
                    <div style="font-size: 11px;">High</div>
                </div>
                <div style="text-align: center; padding: 5px; background: #ffc107; color: black; border-radius: 4px;">
                    <div style="font-weight: bold;">{}</div>
                    <div style="font-size: 11px;">Medium</div>
                </div>
                <div style="text-align: center; padding: 5px; background: #17a2b8; color: white; border-radius: 4px;">
                    <div style="font-weight: bold;">{}</div>
                    <div style="font-size: 11px;">Low</div>
                </div>
                <div style="text-align: center; padding: 5px; background: #6c757d; color: white; border-radius: 4px;">
                    <div style="font-weight: bold;">{}</div>
                    <div style="font-size: 11px;">Info</div>
                </div>
                <div style="text-align: center; padding: 5px; background: #28a745; color: white; border-radius: 4px;">
                    <div style="font-weight: bold;">{}</div>
                    <div style="font-size: 11px;">Total</div>
                </div>
            </div>
            ''',
            obj.critical_severity_count,
            obj.high_severity_count, 
            obj.medium_severity_count,
            obj.low_severity_count,
            obj.info_severity_count,
            obj.total_vulnerabilities
        )
    vulnerability_counts_display.short_description = 'จำนวนช่องโหว่'

    actions = ['mark_as_reviewed', 'export_scan_data']

    def mark_as_reviewed(self, request, queryset):
        """ทำเครื่องหมายว่าตรวจสอบแล้ว"""
        count = queryset.count()
        self.message_user(request, f'ทำเครื่องหมาย {count} รายการว่าตรวจสอบแล้ว')
    mark_as_reviewed.short_description = 'ทำเครื่องหมายว่าตรวจสอบแล้ว'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = [
        'name',
        'scan_result_link',
        'severity_badge', 
        'user_link',
        'scan_date',
        'cwe_id'
    ]
    list_filter = [
        'severity',
        'scan_result__scanned_at',
        'scan_result__user',
        'cwe_id'
    ]
    search_fields = [
        'name', 
        'description',
        'remediation',
        'scan_result__user__username',
        'cwe_id'
    ]
    readonly_fields = ['created_at']
    
    fieldsets = (
        ('ข้อมูลช่องโหว่', {
            'fields': ('scan_result', 'name', 'severity', 'cwe_id')
        }),
        ('รายละเอียด', {
            'fields': ('description', 'remediation', 'attack_scenario')
        }),
        ('โค้ดที่เกี่ยวข้อง', {
            'fields': ('code_snippet',),
            'classes': ('collapse',)
        }),
        ('ข้อมูลระบบ', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('scan_result__user')

    def scan_result_link(self, obj):
        """ลิงก์ไปยัง ScanResult"""
        return format_html(
            '<a href="/admin/scp4/scanresult/{}/change/">Scan #{}</a>',
            obj.scan_result.id,
            obj.scan_result.id
        )
    scan_result_link.short_description = 'ผลการสแกน'

    def user_link(self, obj):
        """ลิงก์ไปยังผู้ใช้"""
        return format_html(
            '<a href="/admin/auth/user/{}/change/">{}</a>',
            obj.scan_result.user.id,
            obj.scan_result.user.username
        )
    user_link.short_description = 'ผู้ใช้'

    def scan_date(self, obj):
        """วันที่สแกน"""
        return obj.scan_result.scanned_at.strftime('%d/%m/%Y %H:%M')
    scan_date.short_description = 'วันที่สแกน'
    scan_date.admin_order_field = 'scan_result__scanned_at'

    def severity_badge(self, obj):
        """Badge แสดง severity"""
        color = obj.severity_color
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px;">{}</span>',
            color,
            obj.severity
        )
    severity_badge.short_description = 'ความรุนแรง'
    severity_badge.admin_order_field = 'severity'


# Customize Admin Site
admin.site.site_header = "AI Code Security Analyzer"
admin.site.site_title = "Security Admin"
admin.site.index_title = "จัดการระบบ"