"""
ไฟล์: scp4/management/commands/populate_knowledge.py

วิธีสร้าง:
1. สร้างโฟลเดอร์: scp4/management/commands/
2. สร้างไฟล์ __init__.py ใน scp4/management/ (ไฟล์ว่างเปล่า)
3. สร้างไฟล์ __init__.py ใน scp4/management/commands/ (ไฟล์ว่างเปล่า)
4. วางโค้ดนี้ในไฟล์ scp4/management/commands/populate_knowledge.py

วิธีรัน:
python manage.py populate_knowledge

โครงสร้างโฟลเดอร์:
scp4/
├── management/
│   ├── __init__.py  (สร้างใหม่ - ไฟล์ว่าง)
│   └── commands/
│       ├── __init__.py  (สร้างใหม่ - ไฟล์ว่าง)
│       └── populate_knowledge.py  (ไฟล์นี้)
├── models.py
├── views.py
└── ...
"""

from django.core.management.base import BaseCommand
from scp4.models import VulnerabilityKnowledge

class Command(BaseCommand):
    help = 'เพิ่มข้อมูล OWASP Top 10 2021 เข้า Knowledge Base'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('กำลังเพิ่มข้อมูล OWASP Top 10 2021...'))
        
        vulnerabilities_data = [
            {
                'name': 'SQL Injection',
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2021 - Injection',
                'severity': 'Critical',
                'description': 'SQL Injection เกิดขึ้นเมื่อผู้โจมตีสามารถแทรก SQL commands ที่เป็นอันตรายเข้าไปในคำสั่ง SQL ที่แอปพลิเคชันใช้สื่อสารกับฐานข้อมูล โดยปกติเกิดจากการนำข้อมูล input จากผู้ใช้มาต่อเข้ากับ SQL query โดยตรงโดยไม่ได้ทำการ validate หรือ escape ที่ถูกต้อง',
                'impact': 'ผู้โจมตีสามารถ: อ่านข้อมูลที่เป็นความลับในฐานข้อมูล, แก้ไขหรือลบข้อมูล, bypass authentication, execute administrative operations บนฐานข้อมูล, และในบางกรณีสามารถ execute commands บน operating system ได้',
                'remediation': '1. ใช้ Parameterized Queries (Prepared Statements) เสมอ\n2. ใช้ ORM (Object-Relational Mapping) ที่มี built-in protection\n3. Validate และ Sanitize input ทุกตัว\n4. ใช้ Least Privilege Principle สำหรับ database accounts\n5. หลีกเลี่ยงการต่อ string โดยตรงใน SQL queries',
                'vulnerable_code_example': '''# Python - Vulnerable Code
username = request.POST.get('username')
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# PHP - Vulnerable Code  
$username = $_POST['username'];
$query = "SELECT * FROM users WHERE username = '$username'";
mysqli_query($conn, $query);''',
                'secure_code_example': '''# Python - Secure Code (Using Parameterized Query)
username = request.POST.get('username')
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))

# PHP - Secure Code (Using Prepared Statement)
$username = $_POST['username'];
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();''',
                'keywords': 'sql,query,execute,select,insert,update,delete,where,database,cursor,mysqli,prepare,statement',
                'reference_url': 'https://owasp.org/Top10/A03_2021-Injection/',
                'is_active': True
            },
            {
                'name': 'Cross-Site Scripting (XSS)',
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021 - Injection',
                'severity': 'High',
                'description': 'XSS เกิดขึ้นเมื่อแอปพลิเคชันรับข้อมูลที่ไม่น่าเชื่อถือและส่งไปยัง web browser โดยไม่ได้ validate หรือ encode ที่เหมาะสม ทำให้ผู้โจมตีสามารถ execute malicious scripts ใน browser ของเหยื่อได้',
                'impact': 'ผู้โจมตีสามารถ: ขโมย session cookies, redirect ผู้ใช้ไปยังเว็บไซต์ปลอม, แก้ไข content ของเว็บไซต์, ติดตั้ง keyloggers, ขโมยข้อมูลส่วนตัว',
                'remediation': '1. Encode output data สำหรับ HTML, JavaScript, CSS และ URL contexts\n2. ใช้ Content Security Policy (CSP) headers\n3. Validate และ Sanitize user input\n4. ใช้ HTTPOnly flag สำหรับ cookies\n5. ใช้ modern frameworks ที่มี auto-escaping',
                'vulnerable_code_example': '''<!-- HTML - Vulnerable Code -->
<div>Welcome, <?php echo $_GET['name']; ?></div>

# Python Flask - Vulnerable Code
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Search results for: {query}</h1>"''',
                'secure_code_example': '''<!-- HTML - Secure Code -->
<div>Welcome, <?php echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); ?></div>

# Python Flask - Secure Code
from markupsafe import escape
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Search results for: {escape(query)}</h1>"''',
                'keywords': 'xss,script,innerHTML,document.write,eval,html,echo,print,render,template,escape,sanitize',
                'reference_url': 'https://owasp.org/Top10/A03_2021-Injection/',
                'is_active': True
            },
            {
                'name': 'Broken Access Control',
                'cwe_id': 'CWE-639',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'severity': 'High',
                'description': 'Broken Access Control เกิดขึ้นเมื่อผู้ใช้สามารถเข้าถึงข้อมูลหรือฟังก์ชันที่พวกเขาไม่ควรมีสิทธิ์',
                'impact': 'ผู้โจมตีสามารถ: เข้าถึงข้อมูลของผู้ใช้คนอื่น, แก้ไขหรือลบข้อมูล, เลื่อนระดับสิทธิ์เป็น admin',
                'remediation': '1. Implement proper authentication และ authorization checks\n2. Deny by default\n3. ตรวจสอบ permissions ทั้ง server-side และ client-side\n4. ใช้ Role-Based Access Control (RBAC)',
                'vulnerable_code_example': '''# Python Flask - Vulnerable Code
@app.route('/user/<user_id>')
def view_profile(user_id):
    user = User.query.get(user_id)
    return render_template('profile.html', user=user)''',
                'secure_code_example': '''# Python Flask - Secure Code
@app.route('/user/<user_id>')
@login_required
def view_profile(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)''',
                'keywords': 'authorization,access,permission,role,admin,user,id,forbidden,401,403,authenticate,login,session',
                'reference_url': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
                'is_active': True
            },
            {
                'name': 'Cryptographic Failures',
                'cwe_id': 'CWE-327',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'severity': 'High',
                'description': 'Cryptographic Failures เกิดจากการใช้ encryption ที่อ่อนแอหรือไม่มีเลย, การเก็บข้อมูลสำคัญแบบ plaintext',
                'impact': 'ผู้โจมตีสามารถ: ขโมยข้อมูลส่วนตัว (passwords, credit cards), ทำ man-in-the-middle attacks, decrypt sensitive data',
                'remediation': '1. ใช้ strong encryption algorithms (AES-256, RSA-2048+)\n2. ใช้ secure hashing สำหรับ passwords (bcrypt, Argon2)\n3. ใช้ HTTPS/TLS\n4. อย่าเก็บข้อมูลสำคัญแบบ plaintext',
                'vulnerable_code_example': '''# Python - Vulnerable Code
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()''',
                'secure_code_example': '''# Python - Secure Code
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())''',
                'keywords': 'password,hash,encrypt,decrypt,md5,sha1,crypto,plaintext,key,ssl,tls,https,secret,token,bcrypt',
                'reference_url': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                'is_active': True
            },
            {
                'name': 'Cross-Site Request Forgery (CSRF)',
                'cwe_id': 'CWE-352',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'severity': 'Medium',
                'description': 'CSRF เป็นการโจมตีที่บังคับให้ผู้ใช้ที่ authenticated แล้วทำ actions ที่ไม่ต้องการ',
                'impact': 'ผู้โจมตีสามารถ: ทำ state-changing operations ในนามของเหยื่อ, transfer เงิน, เปลี่ยน account details',
                'remediation': '1. ใช้ CSRF tokens\n2. ใช้ SameSite cookie attribute\n3. ตรวจสอบ Referer header\n4. Re-authentication สำหรับ sensitive operations',
                'vulnerable_code_example': '''<form action="/transfer-money" method="POST">
    <input name="amount" value="1000">
    <button type="submit">Transfer</button>
</form>''',
                'secure_code_example': '''<form action="/transfer-money" method="POST">
    {% csrf_token %}
    <input name="amount" value="1000">
    <button type="submit">Transfer</button>
</form>''',
                'keywords': 'csrf,token,form,post,cookie,session,samesite,referer,state,transfer',
                'reference_url': 'https://owasp.org/www-community/attacks/csrf',
                'is_active': True
            },
            {
                'name': 'Insecure Deserialization',
                'cwe_id': 'CWE-502',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures',
                'severity': 'Critical',
                'description': 'Insecure Deserialization เกิดขึ้นเมื่อแอปพลิเคชัน deserialize ข้อมูลที่ไม่น่าเชื่อถือ',
                'impact': 'ผู้โจมตีสามารถ: Remote Code Execution (RCE), bypass authentication, privilege escalation',
                'remediation': '1. หลีกเลี่ยงการใช้ native deserialization\n2. ใช้ JSON แทน pickle\n3. Implement digital signatures\n4. Isolate deserialization code',
                'vulnerable_code_example': '''# Python - Vulnerable Code
import pickle
user_data = pickle.loads(request.data)''',
                'secure_code_example': '''# Python - Secure Code
import json
user_data = json.loads(request.data)''',
                'keywords': 'pickle,serialize,deserialize,unserialize,unmarshal,readobject,yaml,load',
                'reference_url': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
                'is_active': True
            },
            {
                'name': 'Command Injection',
                'cwe_id': 'CWE-78',
                'owasp_category': 'A03:2021 - Injection',
                'severity': 'Critical',
                'description': 'Command Injection เกิดขึ้นเมื่อแอปพลิเคชัน execute system commands โดยใช้ข้อมูลจาก user input',
                'impact': 'ผู้โจมตีสามารถ: Execute arbitrary system commands, อ่านหรือแก้ไขไฟล์, ติดตั้ง backdoors',
                'remediation': '1. หลีกเลี่ยงการเรียก system commands\n2. ใช้ APIs แทน shell commands\n3. Validate input อย่างเข้มงวด\n4. ใช้ subprocess ที่ไม่ผ่าน shell',
                'vulnerable_code_example': '''# Python - Vulnerable Code
import os
filename = request.POST['filename']
os.system(f'cat {filename}')''',
                'secure_code_example': '''# Python - Secure Code
import subprocess
filename = request.POST['filename']
if not filename.isalnum():
    return "Invalid filename"
result = subprocess.run(['cat', filename], capture_output=True)''',
                'keywords': 'exec,system,shell,command,os.system,subprocess,popen,eval,backtick,shell_exec',
                'reference_url': 'https://owasp.org/Top10/A03_2021-Injection/',
                'is_active': True
            },
            {
                'name': 'Path Traversal',
                'cwe_id': 'CWE-22',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'severity': 'High',
                'description': 'Path Traversal เกิดขึ้นเมื่อแอปพลิเคชันอนุญาตให้ user input กำหนด file paths โดยไม่ validate',
                'impact': 'ผู้โจมตีสามารถ: อ่านไฟล์ sensitive, overwrite files, execute arbitrary code',
                'remediation': '1. Validate file paths\n2. ใช้ whitelist\n3. ใช้ path normalization\n4. ตรวจสอบว่า path อยู่ใน allowed directory',
                'vulnerable_code_example': '''# Python - Vulnerable Code
filename = request.GET['file']
with open(f'/var/www/uploads/{filename}', 'r') as f:
    content = f.read()''',
                'secure_code_example': '''# Python - Secure Code
import os
filename = request.GET['file']
base_dir = '/var/www/uploads/'
filepath = os.path.normpath(os.path.join(base_dir, filename))
if not filepath.startswith(base_dir):
    return "Invalid path", 400
with open(filepath, 'r') as f:
    content = f.read()''',
                'keywords': 'file,path,directory,open,read,include,require,upload,download,../,traversal',
                'reference_url': 'https://owasp.org/www-community/attacks/Path_Traversal',
                'is_active': True
            },
            {
                'name': 'XML External Entity (XXE)',
                'cwe_id': 'CWE-611',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'severity': 'High',
                'description': 'XXE เกิดขึ้นเมื่อ XML parsers ประมวลผล XML input ที่มี external entity references',
                'impact': 'ผู้โจมตีสามารถ: อ่านไฟล์ local, ทำ SSRF, DoS, port scanning',
                'remediation': '1. Disable external entities\n2. ใช้ JSON แทน XML\n3. Update XML processors\n4. ใช้ whitelist สำหรับ XML schemas',
                'vulnerable_code_example': '''# Python - Vulnerable Code
import xml.etree.ElementTree as ET
tree = ET.fromstring(xml_data)''',
                'secure_code_example': '''# Python - Secure Code
import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_data)''',
                'keywords': 'xml,parse,entity,external,doctype,dtd,simplexml,elementtree,dom,sax',
                'reference_url': 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                'is_active': True
            },
            {
                'name': 'Server-Side Request Forgery (SSRF)',
                'cwe_id': 'CWE-918',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery',
                'severity': 'High',
                'description': 'SSRF เกิดขึ้นเมื่อแอปพลิเคชันดึงข้อมูลจาก URL ที่ user ระบุโดยไม่ validate',
                'impact': 'ผู้โจมตีสามารถ: เข้าถึง internal services, อ่าน cloud metadata, port scanning, bypass firewall',
                'remediation': '1. Validate URLs\n2. ใช้ whitelist\n3. Disable redirects\n4. Block internal IP ranges',
                'vulnerable_code_example': '''# Python - Vulnerable Code
import requests
url = request.GET['url']
response = requests.get(url)''',
                'secure_code_example': '''# Python - Secure Code
import requests
from urllib.parse import urlparse
url = request.GET['url']
parsed = urlparse(url)
allowed_domains = ['api.example.com']
if parsed.netloc not in allowed_domains:
    return "Invalid URL", 400
response = requests.get(url, timeout=5, allow_redirects=False)''',
                'keywords': 'url,fetch,request,curl,wget,http,api,localhost,127.0.0.1,metadata,cloud',
                'reference_url': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
                'is_active': True
            },
        ]
        
        created_count = 0
        updated_count = 0
        
        for vuln_data in vulnerabilities_data:
            vuln, created = VulnerabilityKnowledge.objects.update_or_create(
                name=vuln_data['name'],
                defaults=vuln_data
            )
            
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f'✓ เพิ่ม: {vuln.name} ({vuln.cwe_id})'))
            else:
                updated_count += 1
                self.stdout.write(self.style.WARNING(f'↻ อัพเดท: {vuln.name} ({vuln.cwe_id})'))
        
        self.stdout.write(self.style.SUCCESS(f'\n=== สรุป ==='))
        self.stdout.write(self.style.SUCCESS(f'เพิ่มใหม่: {created_count} รายการ'))
        self.stdout.write(self.style.SUCCESS(f'อัพเดท: {updated_count} รายการ'))
        self.stdout.write(self.style.SUCCESS(f'รวมทั้งหมด: {created_count + updated_count} รายการ'))