from django.db import models
from django.contrib.auth.models import User

class ScanResult(models.Model):
    """
    ผลลัพธ์การสแกนโค้ดแต่ละครั้งของผู้ใช้
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_results', verbose_name="ผู้ใช้")
    scanned_at = models.DateTimeField(auto_now_add=True, verbose_name="วันที่และเวลาที่สแกน")

    scan_duration_seconds = models.IntegerField(null=True, blank=True, verbose_name="ระยะเวลาสแกน (วินาที)")
    ollama_model_version = models.CharField(max_length=100, blank=True, null=True, verbose_name="เวอร์ชัน Ollama Model")
    scanned_code = models.TextField(verbose_name="โค้ดที่ถูกสแกน")
    analysis_result_raw = models.TextField(blank=True, null=True, verbose_name="ผลลัพธ์ดิบจาก AI (ข้อความ)")

    total_vulnerabilities = models.IntegerField(default=0, verbose_name="จำนวนช่องโหว่รวม")
    critical_severity_count = models.IntegerField(default=0, verbose_name="จำนวนช่องโหว่ความรุนแรงวิกฤต")
    high_severity_count = models.IntegerField(default=0, verbose_name="จำนวนช่องโหว่ความรุนแรงสูง")
    medium_severity_count = models.IntegerField(default=0, verbose_name="จำนวนช่องโหว่ความรุนแรงปานกลาง")
    low_severity_count = models.IntegerField(default=0, verbose_name="จำนวนช่องโหว่ความรุนแรงต่ำ")
    info_severity_count = models.IntegerField(default=0, verbose_name="จำนวนช่องโหว่ข้อมูล")

    class Meta:
        verbose_name = "Scan results"
        verbose_name_plural = "Scan results"
        ordering = ['-scanned_at']

    def __str__(self):
        return f"ผลสแกนโดย {self.user.username} เมื่อ {self.scanned_at.strftime('%Y-%m-%d %H:%M')}"

class Vulnerability(models.Model):
    """
    ช่องโหว่ที่ตรวจพบในการสแกน
    """
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Info', 'Info'),
    ]

    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Fixed', 'Fixed'),
        ('False Positive', 'False Positive'),
        ('Accepted Risk', 'Accepted Risk'),
    ]

    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='vulnerabilities', verbose_name="ผลลัพธ์การสแกน")
    name = models.CharField(max_length=255, verbose_name="ชื่อช่องโหว่")
    description = models.TextField(verbose_name="คำอธิบายช่องโหว่")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, verbose_name="ระดับความรุนแรง")

    file_path = models.CharField(max_length=500, blank=True, null=True, verbose_name="ไฟล์ที่พบ")
    line_number = models.IntegerField(blank=True, null=True, verbose_name="บรรทัดที่พบ")
    code_snippet = models.TextField(blank=True, null=True, verbose_name="ส่วนของโค้ดที่เกี่ยวข้อง")
    remediation = models.TextField(blank=True, null=True, verbose_name="คำแนะนำในการแก้ไข")
    owasp_link = models.URLField(max_length=500, blank=True, null=True, verbose_name="ลิงก์ OWASP/ข้อมูลเพิ่มเติม")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open', verbose_name="สถานะ")

    class Meta:
        verbose_name = "ช่องโหว่"
        verbose_name_plural = "ช่องโหว่"
        ordering = ['-severity']

    def __str__(self):
        location = f" in {self.file_path}" if self.file_path else ""
        return f"{self.name} ({self.severity}){location}"


class AnalysisResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='raw_analysis_results', default=1)
    code = models.TextField(verbose_name="โค้ดที่วิเคราะห์")
    result = models.TextField(verbose_name="ผลลัพธ์ดิบจาก AI")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="วันที่วิเคราะห์")

    class Meta:
        verbose_name = "ผลลัพธ์ดิบจากการวิเคราะห์ (Legacy)"
        verbose_name_plural = "ผลลัพธ์ดิบจากการวิเคราะห์ (Legacy)"
        ordering = ['-created_at']

    def __str__(self):
        return f"Analysis @ {self.created_at.strftime('%Y-%m-%d %H:%M:%S')} by {self.user.username if self.user else 'N/A'}"
    
class UserActivityLog(models.Model):
    EVENT_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=10, choices=EVENT_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.event_type} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
    


