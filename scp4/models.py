from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

class ScanResult(models.Model):
    """
    ผลลัพธ์การสแกนโค้ดแต่ละครั้งของผู้ใช้
    """
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='scan_results',
        db_index=True,
        verbose_name="ผู้ใช้"
    )
    scanned_at = models.DateTimeField(
        auto_now_add=True, 
        db_index=True,
        verbose_name="วันที่และเวลาที่สแกน"
    )
    
    # Code and AI Analysis
    scanned_code = models.TextField(verbose_name="โค้ดที่ถูกสแกน")
    analysis_result_raw = models.TextField(
        blank=True, 
        null=True, 
        verbose_name="ผลลัพธ์ดิบจาก AI"
    )
    ai_model_used = models.CharField(
        max_length=100, 
        default="deepseek-coder:6.7b",
        verbose_name="AI Model ที่ใช้"
    )

    # Vulnerability Statistics
    total_vulnerabilities = models.PositiveIntegerField(
        default=0, 
        verbose_name="จำนวนช่องโหว่รวม"
    )
    critical_severity_count = models.PositiveIntegerField(
        default=0, 
        verbose_name="Critical"
    )
    high_severity_count = models.PositiveIntegerField(
        default=0, 
        verbose_name="High"
    )
    medium_severity_count = models.PositiveIntegerField(
        default=0, 
        verbose_name="Medium"
    )
    low_severity_count = models.PositiveIntegerField(
        default=0, 
        verbose_name="Low"
    )
    info_severity_count = models.PositiveIntegerField(
        default=0, 
        verbose_name="Info"
    )

    # 🆕 เพิ่ม Properties เหล่านี้
    @property
    def is_completed(self):
        """
        ตรวจสอบว่าการสแกนเสร็จสิ้นแล้วหรือไม่
        ถือว่าเสร็จสิ้นถ้ามีผลการวิเคราะห์จาก AI
        """
        return bool(self.analysis_result_raw and self.analysis_result_raw.strip())
    
    @property
    def status_display(self):
        """แสดงสถานะเป็นภาษาไทย"""
        return "เสร็จสิ้น" if self.is_completed else "กำลังประมวลผล"
    
    @property
    def status_icon(self):
        """ไอคอนสถานะ"""
        return "✅" if self.is_completed else "⏳"
    
    @property
    def status_color(self):
        """สีสถานะ"""
        return "#4caf50" if self.is_completed else "#ff9800"

    # Properties ที่มีอยู่แล้วเดิม (ต่อจากโค้ดเดิม)
    @property
    def has_high_risk(self):
        """มีช่องโหว่ระดับสูงหรือร้ายแรงหรือไม่"""
        return (self.critical_severity_count + self.high_severity_count) > 0

    @property
    def risk_level(self):
        """ระดับความเสี่ยงโดยรวม"""
        if self.critical_severity_count > 0:
            return "Critical"
        elif self.high_severity_count > 0:
            return "High"
        elif self.medium_severity_count > 0:
            return "Medium"
        elif self.low_severity_count > 0:
            return "Low"
        else:
            return "Safe"

    class Meta:
        verbose_name = "ผลลัพธ์การสแกน"
        verbose_name_plural = "ผลลัพธ์การสแกน"
        ordering = ['-scanned_at']
        indexes = [
            models.Index(fields=['user', '-scanned_at']),
            models.Index(fields=['total_vulnerabilities']),
            models.Index(fields=['scanned_at']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.scanned_at.strftime('%d/%m/%Y %H:%M')}"

    class Meta:
        verbose_name = "ผลลัพธ์การสแกน"
        verbose_name_plural = "ผลลัพธ์การสแกน"
        ordering = ['-scanned_at']
        indexes = [
            models.Index(fields=['user', '-scanned_at']),
            models.Index(fields=['total_vulnerabilities']),
            models.Index(fields=['scanned_at']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.scanned_at.strftime('%d/%m/%Y %H:%M')}"

    @property
    def has_high_risk(self):
        """มีช่องโหว่ระดับสูงหรือร้ายแรงหรือไม่"""
        return (self.critical_severity_count + self.high_severity_count) > 0

    @property
    def risk_level(self):
        """ระดับความเสี่ยงโดยรวม"""
        if self.critical_severity_count > 0:
            return "Critical"
        elif self.high_severity_count > 0:
            return "High"
        elif self.medium_severity_count > 0:
            return "Medium"
        elif self.low_severity_count > 0:
            return "Low"
        else:
            return "Safe"


class Vulnerability(models.Model):
    """
    ช่องโหว่ที่ตรวจพบในการสแกน
    """
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Informational', 'Informational'),
    ]

    scan_result = models.ForeignKey(
        ScanResult, 
        on_delete=models.CASCADE, 
        related_name='vulnerabilities',
        db_index=True,
        verbose_name="ผลลัพธ์การสแกน"
    )
    
    # Core Vulnerability Info
    name = models.CharField(max_length=255, verbose_name="ชื่อช่องโหว่")
    description = models.TextField(verbose_name="คำอธิบาย")
    severity = models.CharField(
        max_length=20, 
        choices=SEVERITY_CHOICES,
        db_index=True,
        verbose_name="ระดับความรุนแรง"
    )
    
    # Code Details
    code_snippet = models.TextField(
        blank=True, 
        null=True, 
        verbose_name="โค้ดที่เกี่ยวข้อง"
    )
    remediation = models.TextField(
        blank=True, 
        null=True, 
        verbose_name="วิธีแก้ไข"
    )
    
    # Additional Info from AI
    cwe_id = models.CharField(
        max_length=20, 
        blank=True, 
        null=True,
        verbose_name="CWE ID"
    )
    attack_scenario = models.TextField(
        blank=True, 
        null=True,
        verbose_name="สถานการณ์การโจมตี"
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "ช่องโหว่"
        verbose_name_plural = "ช่องโหว่"
        ordering = [
            models.Case(
                models.When(severity='Critical', then=models.Value(1)),
                models.When(severity='High', then=models.Value(2)),
                models.When(severity='Medium', then=models.Value(3)),
                models.When(severity='Low', then=models.Value(4)),
                models.When(severity='Informational', then=models.Value(5)),
                default=models.Value(6),
                output_field=models.IntegerField()
            ),
            'name'
        ]
        indexes = [
            models.Index(fields=['scan_result', 'severity']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"{self.name} ({self.severity})"

    @property
    def severity_color(self):
        """สีสำหรับแสดงใน UI"""
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#17a2b8',
            'Informational': '#6c757d',
        }
        return colors.get(self.severity, '#6c757d')


class UserProfile(models.Model):
    """
    ข้อมูลเพิ่มเติมของผู้ใช้
    """
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='profile'
    )
    
    # Preferences
    email_notifications = models.BooleanField(
        default=True,
        verbose_name="รับการแจ้งเตือนทางอีเมล"
    )
    preferred_language = models.CharField(
        max_length=10,
        choices=[('th', 'ไทย'), ('en', 'English')],
        default='th',
        verbose_name="ภาษาที่ต้องการ"
    )
    
    # Statistics
    total_scans_count = models.PositiveIntegerField(
        default=0,
        verbose_name="จำนวนการสแกนทั้งหมด"
    )
    last_scan_date = models.DateTimeField(
        null=True, 
        blank=True,
        verbose_name="การสแกนล่าสุด"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "โปรไฟล์ผู้ใช้"
        verbose_name_plural = "โปรไฟล์ผู้ใช้"

    def __str__(self):
        return f"Profile: {self.user.username}"

    def update_scan_stats(self):
        """อัปเดตสถิติการสแกน"""
        scans = ScanResult.objects.filter(user=self.user)
        self.total_scans_count = scans.count()
        latest_scan = scans.first()
        if latest_scan:
            self.last_scan_date = latest_scan.scanned_at
        self.save()


# Signals สำหรับสร้าง UserProfile อัตโนมัติ
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """สร้าง UserProfile เมื่อมี User ใหม่"""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """บันทึก UserProfile เมื่อบันทึก User"""
    if hasattr(instance, 'profile'):
        instance.profile.save()

@receiver(post_save, sender=ScanResult)
def update_user_profile_stats(sender, instance, created, **kwargs):
    """อัปเดตสถิติใน UserProfile เมื่อมีการสแกนใหม่"""
    if created and hasattr(instance.user, 'profile'):
        instance.user.profile.update_scan_stats()