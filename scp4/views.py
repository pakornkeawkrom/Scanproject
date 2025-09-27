# views.py - Import ที่จัดเรียงและตรวจสอบแล้ว

# Python standard library
import json
import time 
import csv
import os
import sys
import platform
from datetime import datetime, timedelta
from weasyprint import HTML, CSS
from django.http import HttpResponse
from django.contrib.staticfiles import finders

# Django core imports
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.template.loader import render_to_string
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Q, Sum
from django.core.cache import cache
from django.core.exceptions import PermissionDenied

# Django framework imports
import django

# Project-specific imports
from .forms import SignUpForm
from .models import ScanResult, Vulnerability, UserProfile

# Third-party imports (ให้ตรวจสอบว่าติดตั้งแล้วหรือไม่)
import requests




def render_analysis_result_partial(request, scan_result=None, code="", raw_output_text="", ollama_error=False, no_vuln_found=False):
    context = {
        'scan_result': scan_result,
        'code': code,
        'raw_output_text': scan_result.analysis_result_raw if scan_result else raw_output_text, 
        'ollama_error': ollama_error,
        'no_vuln_found': no_vuln_found,
        'vulnerabilities': scan_result.vulnerabilities.all().order_by('-severity') if scan_result else [],
    }
    return render_to_string('scp4/partials/analysis_result.html', context, request=request)

def parse_ollama_output(raw_output_text):
    try:
        # พยายาม parse raw_output_text เป็น JSON ก่อน
        parsed_data = json.loads(raw_output_text)

        if 'vulnerabilities' in parsed_data and isinstance(parsed_data['vulnerabilities'], list):
            vulnerabilities = []
            for item in parsed_data['vulnerabilities']:
                severity = item.get('severity', 'Info').capitalize()
                description = item.get('description', 'No description provided.')
                remediation = item.get('remediation', 'No remediation steps provided.')
                code_snippet = item.get('code_snippet', '')
                name = item.get('name', f"Potential {severity} Vulnerability")

                vulnerabilities.append({
                    'name': name,
                    'severity': severity,
                    'description': description,
                    'remediation': remediation,
                    'code_snippet': code_snippet
                })
            return vulnerabilities

        # ถ้าไม่มี vulnerabilities หรือรูปแบบไม่ตรง ก็ส่งกลับ list ว่าง
        return []

    except json.JSONDecodeError:
        # ถ้า JSON decode ไม่ได้ ให้ fallback ไปใช้ regex แยกข้อมูลจาก raw text
        vulnerabilities = []

        vuln_section_match = re.search(
            r'\*\*Vulnerabilities Found\*\*:\s*\n(.*?)(?=\n\*\*No Vulnerabilities Found\*\*|\n\*\*Best Practices/Suggestions\*\*|\Z)',
            raw_output_text,
            re.DOTALL | re.IGNORECASE
        )

        if vuln_section_match:
            vuln_content = vuln_section_match.group(1)

            vuln_item_pattern = re.compile(
                r'-\s*\*\*Severity\*\*:\s*(?P<severity>Critical|High|Medium|Low|Info)\s*\n'
                r'-\s*\*\*Description\*\*:\s*(?P<description>.*?)\s*\n'
                r'-\s*\*\*Remediation\*\*:\s*(?P<remediation>.*?)(?:\n-\s*\*\*Code Snippet\*\*:\s*\n```(?P<code_snippet>.*?)```)?'
                r'(?=\n-\s*\*\*Severity\*\*|\n\*\*No Vulnerabilities Found\*\*|\n\*\*Best Practices/Suggestions\*\*|\Z|$)',
                re.DOTALL | re.IGNORECASE
            )

            for match in vuln_item_pattern.finditer(vuln_content):
                severity = match.group('severity').strip()
                description = match.group('description').strip()
                remediation = match.group('remediation').strip()
                code_snippet = match.group('code_snippet').strip() if match.group('code_snippet') else ""

                vulnerabilities.append({
                    'name': f"Potential {severity.capitalize()} Vulnerability",
                    'severity': severity.capitalize(),
                    'description': description,
                    'remediation': remediation,
                    'code_snippet': code_snippet
                })

        return vulnerabilities

    except Exception as e:
        print(f"Error during Ollama output parsing: {e}")
        return []

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('scp4:home')
    else:
        form = SignUpForm()
    return render(request, 'scp4/signup.html', {'form': form})

@csrf_exempt
@login_required
def analyze_code_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method.'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON in request body.'}, status=400)

    code = data.get('code', '').strip()
    if not code:
        return JsonResponse({'error': 'Code input cannot be empty.'}, status=400)

    ollama_api_url = 'http://localhost:11434/api/generate'

    prompt = f"""
You are an expert cybersecurity code auditor with 15+ years of experience in penetration testing and secure code review. Your specialty is identifying complex, multi-layered security vulnerabilities that automated tools often miss.

## ANALYSIS METHODOLOGY
1. **Static Analysis**: Examine code flow, data paths, and trust boundaries
2. **Dynamic Thinking**: Consider runtime scenarios and edge cases  
3. **Attack Vector Mapping**: Think like an attacker - what would you target first?
4. **Business Logic**: Look beyond technical flaws to logical vulnerabilities

## CRITICAL VULNERABILITY CATEGORIES TO EXAMINE

**OWASP Top 10 2021 + Critical Additions:**
- **A01: Broken Access Control** (horizontal/vertical privilege escalation, IDOR)
- **A02: Cryptographic Failures** (weak encryption, improper key management, plaintext storage)
- **A03: Injection** (SQL, NoSQL, LDAP, OS Command, Code injection, SSTI)
- **A04: Insecure Design** (missing security controls, threat modeling failures)
- **A05: Security Misconfiguration** (default configs, unnecessary features, debug mode)
- **A06: Vulnerable Components** (outdated libraries, unpatched dependencies)
- **A07: Authentication Failures** (weak passwords, session fixation, brute force)
- **A08: Data Integrity Failures** (insecure deserialization, unsigned/unverified data)
- **A09: Logging Failures** (insufficient logging, log injection, sensitive data in logs)
- **A10: SSRF** (internal network access, cloud metadata exploitation)

**ADDITIONAL CRITICAL PATTERNS:**
- **Race Conditions** (TOCTOU, concurrent access issues)
- **Business Logic Flaws** (workflow bypasses, price manipulation)
- **Memory Safety** (buffer overflows, use-after-free)
- **Timing Attacks** (timing-based information disclosure)
- **Path Traversal** (directory traversal, zip slip)
- **XXE** (XML external entity processing)
- **CSRF** (state-changing operations without proper tokens)
- **Clickjacking** (UI redressing attacks)
- **Mass Assignment** (parameter pollution, over-posting)

## SEVERITY ASSESSMENT CRITERIA

**CRITICAL**: Remote code execution, data breach, system compromise
**HIGH**: Privilege escalation, authentication bypass, sensitive data exposure  
**MEDIUM**: Information disclosure, DoS, security feature bypass
**LOW**: Information leakage, minor configuration issues
**INFO**: Best practice violations, hardening opportunities

## ANALYSIS INSTRUCTIONS

**For EACH vulnerability:**
1. **Identify the root cause** - Why does this vulnerability exist?
2. **Map the attack path** - How would an attacker exploit this?
3. **Assess real-world impact** - What's the business/security impact?
4. **Provide precise fixes** - Include specific code changes

**Look for these COMMON PATTERNS:**
- String concatenation in queries → SQL Injection
- User input in templates → SSTI/XSS  
- File operations with user data → Path Traversal
- Deserialization of untrusted data → RCE
- Missing authorization checks → Access Control
- Weak randomness in security contexts → Predictable tokens
- Error messages revealing system information → Information Disclosure

## OUTPUT FORMAT

Return **ONLY** valid JSON in this exact structure:

```json
{{
    "analysis_summary": "Brief overall assessment focusing on the most critical findings and attack vectors.",
    "vulnerabilities": [
        {{
            "name": "Precise vulnerability name (e.g., 'SQL Injection via User Search', 'Reflected XSS in Error Messages')",
            "severity": "Critical|High|Medium|Low|Informational",
            "cwe_id": "CWE-XXX (if applicable)",
            "description": "Technical explanation: root cause → exploitation method → potential impact. Be specific about how an attacker would exploit this.",
            "remediation": "Step-by-step fix with specific code changes, library recommendations, and configuration updates.",
            "code_snippet": "```language\\n<exact problematic code lines>\\n```",
            "secure_example": "```language\\n<corrected secure version>\\n```",
            "attack_scenario": "Realistic example of how this would be exploited in practice"
        }}
    ],
    "security_score": "X/10 (overall security posture)",
    "priority_fixes": ["List the top 3 most critical issues to fix first"],
    "best_practices_suggestions": [
        "Specific actionable recommendations for defense-in-depth"
    ],
    "no_vulnerabilities_found": true/false
}}
```

## IMPORTANT GUIDELINES

- **Be specific**: Don't just say "SQL Injection" - say "SQL Injection in user search via string concatenation on line X"
- **Think holistically**: Look for vulnerability chains and combined attack scenarios
- **Consider context**: A vulnerability in admin-only code is different from public-facing code  
- **Prioritize by exploitability**: Focus on vulnerabilities that are actually exploitable
- **Provide actionable remediation**: Include specific libraries, functions, or configuration changes

## CODE TO ANALYZE

```
{code}
```

**Remember**: Your job is to find vulnerabilities that could realistically be exploited by attackers. Think like a penetration tester, not just a static analysis tool.
"""

    headers = {'Content-Type': 'application/json'}
    payload = {
        "model": "codellama:7b",
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 3000
        }
    }

    try:
        print(f"Attempting to connect to Ollama at {ollama_api_url} with model '{payload['model']}'...")
        print("DeepSeek Coder กำลังประมวลผล อาจใช้เวลา 3-5 นาที...")
        
        # เพิ่ม timeout เป็น 10 นาที (600 วินาที) สำหรับโมเดลใหญ่
        response = requests.post(
            ollama_api_url, 
            headers=headers, 
            json=payload, 
            timeout=600  # เพิ่มจาก 300 เป็น 600 วินาที (10 นาที)
        )
        response.raise_for_status()
        ollama_data = response.json()
        
    except requests.exceptions.Timeout:
        timeout_error_msg = (
            f"โมเดล DeepSeek Coder ใช้เวลาวิเคราะห์นานเกินไป (เกิน 10 นาที). "
            f"แนะนำให้ลองใช้โค้ดที่สั้นกว่านี้ หรือเปลี่ยนเป็นโมเดลที่เล็กกว่า เช่น deepseek-coder:1.3b"
        )
        scan_result = ScanResult.objects.create(
            user=request.user,
            scanned_at=timezone.now(),
            scanned_code=code,
            analysis_result_raw=timeout_error_msg,
            total_vulnerabilities=0,
            critical_severity_count=0,
            high_severity_count=0,
            medium_severity_count=0,
            low_severity_count=0,
            info_severity_count=0,
        )
        html_content = render_analysis_result_partial(request, scan_result=scan_result, ollama_error=True, no_vuln_found=True)
        return JsonResponse({'error': timeout_error_msg, 'html': html_content}, status=408)
        
    except requests.exceptions.ConnectionError as e:
        connection_error_msg = (
            f"ไม่สามารถเชื่อมต่อกับ Ollama ได้: {e}. "
            f"กรุณาตรวจสอบว่า Ollama server กำลังทำงานอยู่และโมเดล '{payload.get('model')}' พร้อมใช้งาน"
        )
        scan_result = ScanResult.objects.create(
            user=request.user,
            scanned_at=timezone.now(),
            scanned_code=code,
            analysis_result_raw=connection_error_msg,
            total_vulnerabilities=0,
            critical_severity_count=0,
            high_severity_count=0,
            medium_severity_count=0,
            low_severity_count=0,
            info_severity_count=0,
        )
        html_content = render_analysis_result_partial(request, scan_result=scan_result, ollama_error=True, no_vuln_found=True)
        return JsonResponse({'error': connection_error_msg, 'html': html_content}, status=503)
        
    except requests.exceptions.RequestException as e:
        ollama_error_msg = (
            f"Failed to connect to Ollama AI: {e}. "
            f"Please ensure the Ollama server is running and the specified model ('{payload.get('model')}') is available."
        )
        scan_result = ScanResult.objects.create(
            user=request.user,
            scanned_at=timezone.now(),
            scanned_code=code,
            analysis_result_raw=ollama_error_msg,
            total_vulnerabilities=0,
            critical_severity_count=0,
            high_severity_count=0,
            medium_severity_count=0,
            low_severity_count=0,
            info_severity_count=0,
        )
        html_content = render_analysis_result_partial(request, scan_result=scan_result, ollama_error=True, no_vuln_found=True)
        return JsonResponse({'error': ollama_error_msg, 'html': html_content}, status=500)

    raw_output_text = ollama_data.get('response', '{}')
    ollama_error_occurred = False
    no_vuln_found_flag = True
    parsed_vulnerabilities = []

    try:
        analysis_data = json.loads(raw_output_text)
        if 'error' in analysis_data:
            ollama_error_occurred = True
            raw_output_text = analysis_data['error']
        else:
            parsed_vulnerabilities = analysis_data.get('vulnerabilities', [])
            if parsed_vulnerabilities:
                no_vuln_found_flag = False
            else:
                no_vuln_found_flag = analysis_data.get('no_vulnerabilities_found', True)
    except json.JSONDecodeError as e:
        print(f"JSONDecodeError: Ollama's 'response' field is not valid JSON. {e}")
        ollama_error_occurred = True
        raw_output_text = f"AI output format error: {e}. Raw output: {raw_output_text[:200]}..."
        no_vuln_found_flag = True

    # นับ severity จาก vulnerabilities ที่ได้มา
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    # get severity choices from model
    severity_choices = [choice[0] for choice in Vulnerability._meta.get_field('severity').choices]

    for vuln in parsed_vulnerabilities:
        sev = vuln.get('severity', 'Informational').capitalize()
        if sev not in severity_choices:
            sev = 'Informational'

        if sev == 'Critical':
            critical_count += 1
        elif sev == 'High':
            high_count += 1
        elif sev == 'Medium':
            medium_count += 1
        elif sev == 'Low':
            low_count += 1
        elif sev == 'Informational':
            info_count += 1

    # สร้างบันทึก scan result
    scan_result = ScanResult.objects.create(
        user=request.user,
        scanned_at=timezone.now(),
        scanned_code=code,
        analysis_result_raw=raw_output_text,
        total_vulnerabilities=len(parsed_vulnerabilities),
        critical_severity_count=critical_count,
        high_severity_count=high_count,
        medium_severity_count=medium_count,
        low_severity_count=low_count,
        info_severity_count=info_count
    )

    # สร้าง Vulnerability objects
    for vuln in parsed_vulnerabilities:
        sev = vuln.get('severity', 'Informational').capitalize()
        if sev not in severity_choices:
            sev = 'Informational'

        Vulnerability.objects.create(
            scan_result=scan_result,
            name=vuln.get('name', f"Vulnerability {sev}"),
            severity=sev,
            description=vuln.get('description', 'No description provided.'),
            remediation=vuln.get('remediation', 'No remediation steps provided.'),
            code_snippet=vuln.get('code_snippet', '')
        )

    html_content = render_analysis_result_partial(
        request,
        scan_result=scan_result,
        code=code,
        raw_output_text=raw_output_text,
        ollama_error=ollama_error_occurred,
        no_vuln_found=no_vuln_found_flag
    )

    return JsonResponse({'html': html_content, 'scan_result_id': scan_result.id})

def home(request):
    return render(request, 'scp4/home.html')

@login_required
def index(request):
    recent_scans = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')[:3]
    context = {'recent_scans': recent_scans}
    return render(request, 'scp4/index.html', context)

@login_required
def view_scan_result(request, scan_result_id):
    """
    แสดงรายละเอียดผลการวิเคราะห์ช่องโหว่ของโค้ดที่สแกน
    """
    # ตรวจสอบสิทธิ์: Admin ดูได้ทุก scan, User ธรรมดาดูได้แค่ของตัวเอง
    if request.user.is_superuser:
        # Admin ดูได้ทุก scan
        scan_result = get_object_or_404(ScanResult, id=scan_result_id)
        # สำหรับ admin ให้ดู scan อื่นๆ ของ user คนเดียวกับ scan นี้
        other_scans = ScanResult.objects.filter(user=scan_result.user).exclude(id=scan_result_id).order_by('-scanned_at')[:10]
    else:
        # User ธรรมดาดูได้แค่ของตัวเอง
        scan_result = get_object_or_404(ScanResult, id=scan_result_id, user=request.user)
        # ดึงประวัติการสแกนทั้งหมดของ user คนนี้ (ยกเว้นรายการปัจจุบัน)
        other_scans = ScanResult.objects.filter(user=request.user).exclude(id=scan_result_id).order_by('-scanned_at')[:10]

    # ดึงช่องโหว่ที่เกี่ยวข้องและเรียงตามความรุนแรง
    vulnerabilities = scan_result.vulnerabilities.all().order_by('-severity')

    # ตรวจสอบว่าไม่พบช่องโหว่
    no_vuln_found = not vulnerabilities.exists()

    # ตรวจสอบว่ามีข้อความแสดงข้อผิดพลาดจาก Ollama AI
    ollama_error_occurred = False
    error_signatures = [
        "Failed to connect to Ollama AI:",
        "AI output format error:",
        "An error occurred while processing AI response:",
        "An unexpected error occurred:"
    ]
    if scan_result.analysis_result_raw:
        for signature in error_signatures:
            if signature in scan_result.analysis_result_raw:
                ollama_error_occurred = True
                break
    
    # คำนวณสถิติช่องโหว่
    total_vulnerabilities = vulnerabilities.count()
    high_severity_count = vulnerabilities.filter(severity__in=['Critical', 'High']).count()
    medium_severity_count = vulnerabilities.filter(severity='Medium').count()
    low_severity_count = vulnerabilities.filter(severity='Low').count()

    # เตรียม Context สำหรับส่งไปที่ Template
    context = {
        'scan_result': scan_result,
        'code': scan_result.scanned_code,
        'raw_output_text': scan_result.analysis_result_raw,
        'no_vuln_found': no_vuln_found,
        'vulnerabilities': vulnerabilities,
        'ollama_error': ollama_error_occurred,
        'other_scans': other_scans,  # รายการสแกนอื่นๆ
        'total_vulnerabilities': total_vulnerabilities,
        'high_severity_count': high_severity_count,
        'medium_severity_count': medium_severity_count,
        'low_severity_count': low_severity_count,
        'current_scan_id': scan_result_id,  # เพื่อให้รู้ว่ากำลังดูรายการไหนอยู่
    }

    # Render Template ที่ถูกต้อง - ใช้ template เฉพาะสำหรับดูรายละเอียด
    return render(request, 'scp4/scan_result_detail.html', context)

@login_required
def export_scan_report_pdf(request, scan_result_id):
    # ตรวจสอบสิทธิ์เหมือนกัน
    if request.user.is_superuser:
        scan_result = get_object_or_404(ScanResult, id=scan_result_id)
    else:
        scan_result = get_object_or_404(ScanResult, id=scan_result_id, user=request.user)

    # ดึง vulnerabilities ที่เกี่ยวข้อง พร้อมเรียงลำดับตาม severity ลดหลั่น
    vulnerabilities = scan_result.vulnerabilities.all().order_by('-severity')

    no_vuln_found_for_pdf = not vulnerabilities.exists()

    # ตรวจสอบว่ามี error เกี่ยวกับการเชื่อมต่อ Ollama หรือการประมวลผล AI หรือไม่
    ollama_error_occurred_for_pdf = False
    error_signatures = [
        "Failed to connect to Ollama AI:",
        "AI output format error:",
        "An error occurred while processing AI response:",
        "An unexpected error occurred:"
    ]
    if any(signature in scan_result.analysis_result_raw for signature in error_signatures):
        ollama_error_occurred_for_pdf = True

    context = {
        'scan_result': scan_result,
        'code': scan_result.scanned_code,
        'raw_output_text': scan_result.analysis_result_raw,
        'no_vuln_found': no_vuln_found_for_pdf,
        'current_date': datetime.now().strftime("%d %B %Y %H:%M:%S"),
        'vulnerabilities': vulnerabilities,
        'ollama_error': ollama_error_occurred_for_pdf,
    }

    # สร้าง HTML จาก template และ context
    html_string = render_to_string('scp4/pdf_report_template.html', context)

    # โหลด CSS สำหรับสไตล์ PDF
    css_path = os.path.join(settings.STATIC_ROOT, 'css', 'pdf_report.css')
    css_string = ""
    if os.path.exists(css_path):
        with open(css_path, 'r', encoding='utf-8') as f:
            css_string = f.read()
    else:
        print(f"Warning: PDF CSS file not found at {css_path}. PDF might not be styled correctly.")

    # สร้าง PDF จาก HTML พร้อม CSS
    html = HTML(string=html_string)
    pdf_file = html.write_pdf(stylesheets=[CSS(string=css_string)])

    # ส่งไฟล์ PDF กลับเป็น HTTP response พร้อม header ดาวน์โหลด
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="scan_report_{scan_result.id}.pdf"'
    return response

@login_required  
def scan_history(request):
    """
    หน้าประวัติการสแกนทั้งหมด
    """
    # ดึงประวัติทั้งหมดของ user เรียงจากใหม่ไปเก่า
    all_scans = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')
    
    # เพิ่มการแบ่งหน้า (pagination) ถ้าจำเป็น
    from django.core.paginator import Paginator
    paginator = Paginator(all_scans, 10)  # แสดง 10 รายการต่อหน้า
    page_number = request.GET.get('page')
    page_scans = paginator.get_page(page_number)
    
    context = {
        'all_scans': page_scans,
        'total_scans': all_scans.count(),
    }
    return render(request, 'scp4/scan_history.html', context)

@login_required
def delete_scan_result(request, result_id):
    """
    ลบผลการสแกนพร้อมหน้ายืนยัน
    """
    # ตรวจสอบสิทธิ์: Admin ลบได้ทุก scan, User ธรรมดาลบได้แค่ของตัวเอง
    if request.user.is_superuser:
        scan_result = get_object_or_404(ScanResult, id=result_id)
    else:
        scan_result = get_object_or_404(ScanResult, id=result_id, user=request.user)
    
    # ✅ เพิ่ม: ป้องกัน staff ลบ scan ของ superuser
    if request.user.is_staff and not request.user.is_superuser and scan_result.user.is_superuser:
        messages.error(request, 'คุณไม่มีสิทธิ์ลบข้อมูลของผู้ดูแลระบบสูงสุด')
        referrer = request.META.get('HTTP_REFERER', '')
        if 'admin' in referrer:
            return redirect('scp4:admin_scans')
        return redirect('scp4:scan_history')
    
    if request.method == 'POST':
        # ตรวจสอบการยืนยันการลบ
        if request.POST.get('confirm_delete') == 'yes':
            scan_result.delete()
            messages.success(request, 'ลบประวัติการสแกนเรียบร้อยแล้ว')
            
            # ตรวจสอบว่ามาจากหน้าไหนแล้ว redirect กลับไป
            referrer = request.META.get('HTTP_REFERER', '')
            if 'admin' in referrer:
                return redirect('scp4:admin_scans')  # กลับไปหน้า admin
            elif 'history' in referrer:
                return redirect('scp4:scan_history')  # กลับไปหน้าประวัติ
            else:
                return redirect('scp4:index')  # กลับไปหน้าแรก
        else:
            # ถ้าไม่ยืนยัน ให้กลับไปหน้าเดิม
            referrer = request.META.get('HTTP_REFERER', '')
            if 'admin' in referrer:
                return redirect('scp4:admin_scans')
            elif 'history' in referrer:
                return redirect('scp4:scan_history')
            else:
                return redirect('scp4:index')
    
    # สำหรับ GET request - แสดงหน้ายืนยันการลบ
    referrer = request.META.get('HTTP_REFERER', '')
    from_history = 'history' in referrer
    from_admin = 'admin' in referrer
    
    context = {
        'scan_result': scan_result,
        'from_history': from_history,
        'from_admin': from_admin,
    }
    return render(request, 'scp4/confirm_delete.html', context)

@csrf_exempt
@require_POST
def delete_scan_result_ajax(request, result_id):
    """
    ลบผลการสแกนผ่าน AJAX
    """
    try:
        # ตรวจสอบสิทธิ์เหมือนกัน
        if request.user.is_superuser:
            scan_result = get_object_or_404(ScanResult, pk=result_id)
        else:
            scan_result = get_object_or_404(ScanResult, pk=result_id, user=request.user)
        
        # ✅ เพิ่ม: ป้องกัน staff ลบ scan ของ superuser
        if request.user.is_staff and not request.user.is_superuser and scan_result.user.is_superuser:
            return JsonResponse({
                'success': False, 
                'message': 'คุณไม่มีสิทธิ์ลบข้อมูลของผู้ดูแลระบบสูงสุด'
            }, status=403)
        
        scan_result.delete()
        return JsonResponse({
            'success': True, 
            'message': 'ลบประวัติการสแกนเรียบร้อยแล้ว'
        })
    except Exception as e:
        return JsonResponse({
            'success': False, 
            'message': f'เกิดข้อผิดพลาด: {str(e)}'
        }, status=500)
    
@login_required
def profile(request):
    """
    แสดงหน้าจัดการข้อมูลส่วนตัว
    """
    # คำนวณสถิติของผู้ใช้
    user_scans = ScanResult.objects.filter(user=request.user)
    total_scans = user_scans.count()
    total_vulnerabilities = user_scans.aggregate(
        total=Sum('total_vulnerabilities')
    )['total'] or 0
    high_risk_count = user_scans.aggregate(
        high_risk=Sum('critical_severity_count') + Sum('high_severity_count')
    )['high_risk'] or 0

    context = {
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'high_risk_count': high_risk_count,
    }
    return render(request, 'scp4/profile.html', context)

@login_required
def update_profile(request):
    """
    อัปเดตข้อมูลส่วนตัว
    """
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()
        user.email = request.POST.get('email', '').strip()
        
        try:
            user.save()
            messages.success(request, 'อัปเดตข้อมูลส่วนตัวเรียบร้อยแล้ว')
        except Exception as e:
            messages.error(request, f'เกิดข้อผิดพลาด: {str(e)}')
    
    return redirect('scp4:profile')

@login_required
def change_password(request):
    """
    เปลี่ยนรหัสผ่าน
    """
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        
        # ตรวจสอบรหัสผ่านปัจจุบัน
        if not request.user.check_password(current_password):
            messages.error(request, 'รหัสผ่านปัจจุบันไม่ถูกต้อง')
            return redirect('scp4:profile')
        
        # ตรวจสอบรหัสผ่านใหม่
        if new_password1 != new_password2:
            messages.error(request, 'รหัสผ่านใหม่ไม่ตรงกัน')
            return redirect('scp4:profile')
        
        if len(new_password1) < 8:
            messages.error(request, 'รหัสผ่านควรมีความยาวอย่างน้อย 8 ตัวอักษร')
            return redirect('scp4:profile')
        
        # เปลี่ยนรหัสผ่าน
        try:
            request.user.set_password(new_password1)
            request.user.save()
            update_session_auth_hash(request, request.user)  # Keep user logged in
            messages.success(request, 'เปลี่ยนรหัสผ่านเรียบร้อยแล้ว')
        except Exception as e:
            messages.error(request, f'เกิดข้อผิดพลาด: {str(e)}')
    
    return redirect('scp4:profile')

@login_required
def export_all_data(request):
    """
    ส่งออกข้อมูลทั้งหมดของผู้ใช้เป็น CSV
    """
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="my_scan_data_{datetime.now().strftime("%Y%m%d")}.csv"'
    
    # เพิ่ม BOM สำหรับ UTF-8
    response.write('\ufeff')
    
    writer = csv.writer(response)
    
    # Header
    writer.writerow([
        'วันที่สแกน',
        'จำนวนช่องโหว่ทั้งหมด', 
        'ความเสี่ยงร้ายแรง',
        'ความเสี่ยงสูง',
        'ความเสี่ยงปานกลาง',
        'ความเสี่ยงต่ำ',
        'ข้อมูลเพิ่มเติม'
    ])
    
    # ข้อมูลการสแกน
    scans = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')
    for scan in scans:
        writer.writerow([
            scan.scanned_at.strftime('%d/%m/%Y %H:%M:%S'),
            scan.total_vulnerabilities,
            scan.critical_severity_count,
            scan.high_severity_count,
            scan.medium_severity_count,
            scan.low_severity_count,
            scan.info_severity_count
        ])
    
    return response

@login_required
def delete_account(request):
    """
    ลบบัญชีผู้ใช้และข้อมูลทั้งหมด
    """
    if request.method == 'POST':
        user = request.user
        username = user.username
        
        try:
            # ลบข้อมูลการสแกนทั้งหมดของผู้ใช้
            ScanResult.objects.filter(user=user).delete()
            
            # ลบบัญชีผู้ใช้
            user.delete()
            
            messages.success(request, f'ลบบัญชี {username} เรียบร้อยแล้ว')
            return redirect('scp4:home')
            
        except Exception as e:
            messages.error(request, f'เกิดข้อผิดพลาดในการลบบัญชี: {str(e)}')
            return redirect('scp4:profile')
    
    return redirect('scp4:profile')

# ✅ เปลี่ยน function ตรวจสอบสิทธิ์
def is_admin_user(user):
    """ตรวจสอบว่าเป็น superuser หรือ staff"""
    return user.is_superuser or user.is_staff

# ✅ แก้ custom_admin - เปลี่ยนจาก is_superuser เป็น is_admin_user
@login_required
@user_passes_test(is_admin_user)  # เปลี่ยนจาก is_superuser
def custom_admin(request):
    """หน้า Dashboard หลักของ Custom Admin"""
    
    # สถิติพื้นฐาน
    total_users = User.objects.count()
    active_users = User.objects.filter(last_login__gte=timezone.now() - timedelta(days=30)).count()
    total_scans = ScanResult.objects.count()
    
    # สถิติการสแกนย้อนหลัง 7 วัน
    week_ago = timezone.now() - timedelta(days=7)
    recent_scans = ScanResult.objects.filter(scanned_at__gte=week_ago).count()
    
    # สถิติช่องโหว่
    vulnerability_stats = ScanResult.objects.aggregate(
        total_vulnerabilities=Sum('total_vulnerabilities'),
        critical_count=Sum('critical_severity_count'),
        high_count=Sum('high_severity_count'),
        medium_count=Sum('medium_severity_count'),
        low_count=Sum('low_severity_count')
    )
    
    # ผู้ใช้ที่ active ล่าสุด
    recent_users = User.objects.filter(
        last_login__isnull=False
    ).order_by('-last_login')[:5]
    
    # การสแกนล่าสุด
    recent_scan_results = ScanResult.objects.select_related('user').order_by('-scanned_at')[:10]
    
    # สถิติรายวัน (7 วันย้อนหลัง)
    daily_stats = []
    for i in range(7):
        date = timezone.now().date() - timedelta(days=i)
        scans_count = ScanResult.objects.filter(scanned_at__date=date).count()
        daily_stats.append({
            'date': date.strftime('%m/%d'),
            'scans': scans_count
        })
    daily_stats.reverse()  # เรียงจากเก่าไปใหม่
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_scans': total_scans,
        'recent_scans': recent_scans,
        'vulnerability_stats': vulnerability_stats,
        'recent_users': recent_users,
        'recent_scan_results': recent_scan_results,
        'daily_stats': json.dumps(daily_stats),
    }
    
    return render(request, 'scp4/custom_admin.html', context)

# ✅ แก้ admin_users
@login_required
@user_passes_test(is_admin_user)  # เปลี่ยนจาก is_superuser
def admin_users(request):
    """จัดการผู้ใช้"""
    
    # ดึงข้อมูลผู้ใช้พร้อมสถิติ
    users = User.objects.annotate(
        scan_count=Count('scan_results'),
        total_vulnerabilities=Sum('scan_results__total_vulnerabilities')
    ).order_by('-date_joined')
    
    # กรองตาม search query
    search_query = request.GET.get('search', '')
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query)
        )
    
    context = {
        'users': users,
        'search_query': search_query,
        'total_users': users.count(),
    }
    
    return render(request, 'scp4/admin_users.html', context)

# ✅ แก้ admin_scans
@login_required
@user_passes_test(is_admin_user)  # เปลี่ยนจาก is_superuser
def admin_scans(request):
    """จัดการการสแกน"""
    
    scans = ScanResult.objects.select_related('user').order_by('-scanned_at')
    
    # เพิ่มการกรองที่ขาดหายไป
    user_search = request.GET.get('user_search', '')
    severity = request.GET.get('severity', '')
    date_range = request.GET.get('date_range', '')
    
    # กรองตาม user_search
    if user_search:
        scans = scans.filter(
            Q(user__username__icontains=user_search) |
            Q(user__email__icontains=user_search) |
            Q(user__first_name__icontains=user_search) |
            Q(user__last_name__icontains=user_search)
        )
    
    # กรองตาม severity
    if severity:
        if severity == 'critical':
            scans = scans.filter(critical_severity_count__gt=0)
        elif severity == 'high':
            scans = scans.filter(high_severity_count__gt=0)
        elif severity == 'medium':
            scans = scans.filter(medium_severity_count__gt=0)
        elif severity == 'low':
            scans = scans.filter(low_severity_count__gt=0)
        elif severity == 'clean':
            scans = scans.filter(total_vulnerabilities=0)
    
    # กรองตามช่วงเวลา
    from datetime import datetime, timedelta
    if date_range:
        now = timezone.now()
        if date_range == 'today':
            scans = scans.filter(scanned_at__date=now.date())
        elif date_range == 'week':
            week_ago = now - timedelta(days=7)
            scans = scans.filter(scanned_at__gte=week_ago)
        elif date_range == 'month':
            month_ago = now - timedelta(days=30)
            scans = scans.filter(scanned_at__gte=month_ago)
    
    # คำนวณสถิติ
    all_scans = ScanResult.objects.all()
    total_scans_all = all_scans.count()
    critical_scans = all_scans.filter(critical_severity_count__gt=0).count()
    high_risk_scans = all_scans.filter(high_severity_count__gt=0).count()
    clean_scans = all_scans.filter(total_vulnerabilities=0).count()
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(scans, 20)
    page_number = request.GET.get('page')
    page_scans = paginator.get_page(page_number)
    
    context = {
        'page_scans': page_scans,
        'total_scans': scans.count(),  # จำนวนหลังกรอง
        'total_scans_all': total_scans_all,  # จำนวนทั้งหมด
        'critical_scans': critical_scans,
        'high_risk_scans': high_risk_scans, 
        'clean_scans': clean_scans,
        'user_search': user_search,
        'severity': severity,
        'date_range': date_range,
    }
    
    return render(request, 'scp4/admin_scans.html', context)

# ✅ แก้ admin_system
@login_required
@user_passes_test(is_admin_user)
def admin_system(request):
    """ตั้งค่าระบบและบำรุงรักษา"""
    
    # ข้อมูลระบบพื้นฐาน
    system_info = {
        'django_version': django.get_version(),
        'python_version': sys.version.split()[0],
        'debug_mode': settings.DEBUG,
        'database_engine': settings.DATABASES['default']['ENGINE'].split('.')[-1],
    }
    
    # สถิติฐานข้อมูล
    db_stats = {
        'total_users': User.objects.count(),
        'total_scans': ScanResult.objects.count(),
        'total_vulnerabilities': Vulnerability.objects.count(),
        'total_profiles': UserProfile.objects.count(),
    }
    
    # สถิติความปลอดภัยแยกตาม severity
    critical_vulnerabilities = Vulnerability.objects.filter(severity='Critical').count()
    high_vulnerabilities = Vulnerability.objects.filter(severity='High').count()
    medium_vulnerabilities = Vulnerability.objects.filter(severity='Medium').count()
    
    # การสแกนใน 7 วันย้อนหลัง
    week_ago = timezone.now() - timedelta(days=7)
    recent_scans = ScanResult.objects.filter(scanned_at__gte=week_ago).count()
    
    # ผู้ใช้ไม่ active
    inactive_threshold = timezone.now() - timedelta(days=90)
    inactive_users = User.objects.filter(
        Q(last_login__lt=inactive_threshold) | Q(last_login__isnull=True)
    ).count()
    
    context = {
        # ข้อมูลระบบ
        **system_info,
        **db_stats,
        
        # สถิติความปลอดภัย
        'critical_vulnerabilities': critical_vulnerabilities,
        'high_vulnerabilities': high_vulnerabilities, 
        'medium_vulnerabilities': medium_vulnerabilities,
        'recent_scans': recent_scans,
        'inactive_users': inactive_users,
    }
    
    return render(request, 'scp4/admin_system.html', context)
