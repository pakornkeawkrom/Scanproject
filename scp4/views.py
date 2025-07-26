import json
import re
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.template.loader import render_to_string
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from .forms import SignUpForm
from .models import ScanResult, Vulnerability
import requests
from datetime import datetime
from django.utils import timezone

from weasyprint import HTML, CSS
from django.conf import settings
import os

from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.shortcuts import redirect
from django.http import JsonResponse
import json

@login_required
@require_POST
def clear_scan_history(request):
    # ลบประวัติการสแกนของ user ปัจจุบัน
    ScanResult.objects.filter(user=request.user).delete()
    return redirect('scp4:index')


@login_required
@require_POST
def delete_selected_scans(request):
    try:
        data = json.loads(request.body)
        selected_scan_ids = data.get('scan_ids', [])

        if not selected_scan_ids:
            return JsonResponse({'status': 'error', 'message': 'No scan results selected.'}, status=400)

        deleted_count, _ = ScanResult.objects.filter(
            id__in=selected_scan_ids, 
            user=request.user  # กรองด้วย user ตรงๆ
        ).delete()

        return JsonResponse({'status': 'success', 'deleted_count': deleted_count})
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format.'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)



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
        
        return []

    except json.JSONDecodeError:
        print("Ollama response is not valid JSON. Attempting regex parsing as a fallback.")
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


def home(request):
    return render(request, 'scp4/home.html')

@login_required
def index(request):
    # ดึงประวัติ scan ของ user
    scan_results = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')
    context = {
        'scan_results': scan_results,
    }
    return render(request, 'scp4/index.html', context)


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
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            code = data.get('code', '').strip()

            if not code:
                return JsonResponse({'error': 'Code input cannot be empty.'}, status=400)

            ollama_api_url = 'http://localhost:11434/api/generate'
            
            prompt = f"""
            You are an AI code security reviewer specializing in identifying vulnerabilities, security best practices, and potential risks across various programming languages.

            Analyze the following code snippet thoroughly. For each vulnerability found, provide:
            1.  **Name**: A concise name for the vulnerability (e.g., "SQL Injection", "Cross-Site Scripting").
            2.  **Severity**: One of: Critical, High, Medium, Low, Informational.
            3.  **Description**: A clear explanation of what the vulnerability is, why it's a risk, and its potential impact. Keep it detailed but concise.
            4.  **Remediation**: Actionable steps to fix the vulnerability and improve security.
            5.  **Code Snippet**: The specific lines of code from the input that are relevant to this vulnerability. Enclose code snippets in triple backticks (```).

            If no significant vulnerabilities are found, explicitly state "No vulnerabilities found" and provide a brief positive assessment.
            Also, include any general security best practices or suggestions relevant to the code.

            Provide your response in **JSON format** as specified below. Ensure the JSON is well-formed and valid.

            ```json
            {{
              "analysis_summary": "A brief overall summary of the scan results.",
              "vulnerabilities": [
                {{
                  "name": "Vulnerability Name (e.g., SQL Injection)",
                  "severity": "High",
                  "description": "Detailed explanation of the vulnerability and its impact...",
                  "remediation": "Actionable steps to fix it...",
                  "code_snippet": "```\nrelevant code here\n```"
                }},
              ],
              "best_practices_suggestions": [
                "Suggestion 1: Use parameterized queries to prevent SQL injection.",
                "Suggestion 2: Validate all user inputs rigorously.",
              ],
              "no_vulnerabilities_found": true/false
            }}
            ```

            If you cannot perform the analysis or encounter an internal error, output a simple JSON object like `{{ "error": "Reason for error." }}`.

            Code to analyze:
            ```
            {code}
            ```
            """

            headers = {'Content-Type': 'application/json'}
            payload = {
                "model": "deepseek-coder",
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }

            print(f"Attempting to connect to Ollama at {ollama_api_url} with model '{payload['model']}'...")
            response_from_ollama = requests.post(ollama_api_url, headers=headers, json=payload, timeout=300)
            response_from_ollama.raise_for_status()
            ollama_data = response_from_ollama.json()
            
            raw_output_text = ollama_data.get('response', '{}')

            ollama_error_occurred = False
            parsed_analysis_data = {}
            parsed_vulnerabilities = []
            no_vuln_found_flag = True

            try:
                parsed_analysis_data = json.loads(raw_output_text)
                
                if 'error' in parsed_analysis_data:
                    ollama_error_occurred = True
                    raw_output_text = parsed_analysis_data['error']
                else:
                    if 'vulnerabilities' in parsed_analysis_data and isinstance(parsed_analysis_data['vulnerabilities'], list):
                        parsed_vulnerabilities = parsed_analysis_data['vulnerabilities']
                        if parsed_vulnerabilities:
                            no_vuln_found_flag = False
                        elif parsed_analysis_data.get('no_vulnerabilities_found', False):
                            no_vuln_found_flag = True
                        else:
                            no_vuln_found_flag = True 
                    else:
                        no_vuln_found_flag = True

            except json.JSONDecodeError as json_e:
                print(f"JSONDecodeError: Ollama's 'response' field is not valid JSON. {json_e}")
                ollama_error_occurred = True
                raw_output_text = f"AI output format error: {json_e}. Raw output: {raw_output_text[:200]}..."
                no_vuln_found_flag = True
            except Exception as parse_e:
                print(f"Error parsing AI response: {parse_e}")
                ollama_error_occurred = True
                raw_output_text = f"An error occurred while processing AI response: {parse_e}. Raw output: {raw_output_text[:200]}..."
                no_vuln_found_flag = True
            
            print(f"Parsed {len(parsed_vulnerabilities)} vulnerabilities from Ollama output.")
            print(f"No vulnerabilities found flag: {no_vuln_found_flag}")

            total_vulnerabilities = len(parsed_vulnerabilities)
            critical_severity_count = 0
            high_severity_count = 0
            medium_severity_count = 0
            low_severity_count = 0
            info_severity_count = 0

            scan_result = ScanResult.objects.create(
                user=request.user,
                scanned_at=timezone.now(),
                scanned_code=code,
                analysis_result_raw=raw_output_text,
                total_vulnerabilities=total_vulnerabilities,
                critical_severity_count=critical_severity_count,
                high_severity_count=high_severity_count,
                medium_severity_count=medium_severity_count,
                low_severity_count=low_severity_count,
                info_severity_count=info_severity_count
            )

            for pv in parsed_vulnerabilities:
                severity_val = pv.get('severity', 'Info').capitalize()
                if severity_val not in [choice[0] for choice in Vulnerability._meta.get_field('severity').choices]:
                    severity_val = 'Info'

                if severity_val == 'Critical': critical_severity_count += 1
                elif severity_val == 'High': high_severity_count += 1
                elif severity_val == 'Medium': medium_severity_count += 1
                elif severity_val == 'Low': low_severity_count += 1
                elif severity_val == 'Info': info_severity_count += 1

                Vulnerability.objects.create(
                    scan_result=scan_result,
                    name=pv.get('name', f"Vulnerability {severity_val}"),
                    severity=severity_val,
                    description=pv.get('description', 'No description provided.'),
                    remediation=pv.get('remediation', 'No remediation steps provided.'), 
                    code_snippet=pv.get('code_snippet', '')
                )
            
            scan_result.total_vulnerabilities = scan_result.vulnerabilities.count()
            scan_result.critical_severity_count = critical_severity_count
            scan_result.high_severity_count = high_severity_count
            scan_result.medium_severity_count = medium_severity_count
            scan_result.low_severity_count = low_severity_count
            scan_result.info_severity_count = info_severity_count
            scan_result.save()

            html_content = render_analysis_result_partial(
                request,
                scan_result=scan_result,
                code=code,
                raw_output_text=raw_output_text,
                ollama_error=ollama_error_occurred,
                no_vuln_found=no_vuln_found_flag
            )

            return JsonResponse({'html': html_content, 'scan_result_id': scan_result.id})

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to Ollama: {e}")
            ollama_error_msg = f"Failed to connect to Ollama AI: {e}. Please ensure the Ollama server is running and the specified model ('{payload.get('model', 'deepseek-coder')}') is available."
            scan_result = ScanResult.objects.create(
                user=request.user,
                scanned_at=timezone.now(),
                scanned_code=code,
                analysis_result_raw=ollama_error_msg,
                total_vulnerabilities=0,
                critical_severity_count=0, high_severity_count=0, 
                medium_severity_count=0, low_severity_count=0, info_severity_count=0
            )
            html_content = render_analysis_result_partial(request, scan_result=scan_result, ollama_error=True, no_vuln_found=True)
            return JsonResponse({'error': ollama_error_msg, 'html': html_content}, status=500)
        except json.JSONDecodeError:
            print("JSONDecodeError: Invalid JSON in request body.")
            return JsonResponse({'error': 'Invalid JSON in request body.'}, status=400)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            scan_result = ScanResult.objects.create(
                user=request.user,
                scanned_at=timezone.now(),
                scanned_code=code,
                analysis_result_raw=f"An unexpected error occurred: {e}",
                total_vulnerabilities=0,
                critical_severity_count=0, high_severity_count=0, 
                medium_severity_count=0, low_severity_count=0, info_severity_count=0
            )
            html_content = render_analysis_result_partial(request, scan_result=scan_result, ollama_error=True, no_vuln_found=True)
            return JsonResponse({'error': f'An unexpected server error occurred: {e}', 'html': html_content}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=405)


@login_required
def view_scan_result(request, scan_result_id):
    scan_result = get_object_or_404(ScanResult, id=scan_result_id, user=request.user)

    vulnerabilities = scan_result.vulnerabilities.all().order_by('-severity') 
    no_vuln_found = not vulnerabilities.exists() 
    
    ollama_error_occurred = False
    error_msgs = [
        "Failed to connect to Ollama AI:",
        "AI output format error:",
        "An error occurred while processing AI response:",
        "An unexpected error occurred:",
    ]
    if any(msg in scan_result.analysis_result_raw for msg in error_msgs):
        ollama_error_occurred = True

    # ดึง list scan result ของ user ด้วย
    scan_results = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')

    context = {
        'scan_result': scan_result,
        'code': scan_result.scanned_code,
        'raw_output_text': scan_result.analysis_result_raw,
        'no_vuln_found': no_vuln_found,
        'vulnerabilities': vulnerabilities,
        'ollama_error': ollama_error_occurred,
        'scan_results': scan_results,
        'current_scan_id': scan_result_id,
    }
    return render(request, 'scp4/scan_result_detail.html', context)



@login_required
def export_scan_report_pdf(request, scan_result_id):
    # แก้ตรงนี้
    scan_result = get_object_or_404(ScanResult, id=scan_result_id, user=request.user)

    vulnerabilities = scan_result.vulnerabilities.all().order_by('-severity')

    no_vuln_found_for_pdf = not vulnerabilities.exists()

    ollama_error_occurred_for_pdf = False
    if "Failed to connect to Ollama AI:" in scan_result.analysis_result_raw or \
       "AI output format error:" in scan_result.analysis_result_raw or \
       "An error occurred while processing AI response:" in scan_result.analysis_result_raw or \
       "An unexpected error occurred:" in scan_result.analysis_result_raw:
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

    html_string = render_to_string('scp4/pdf_report_template.html', context)

    css_path = os.path.join(settings.STATIC_ROOT, 'css', 'pdf_report.css')
    css_string = ""
    if os.path.exists(css_path):
        with open(css_path, 'r', encoding='utf-8') as f:
            css_string = f.read()
    else:
        print(f"Warning: PDF CSS file not found at {css_path}. PDF might not be styled correctly.")

    html = HTML(string=html_string)
    pdf_file = html.write_pdf(stylesheets=[CSS(string=css_string)])

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="scan_report_{scan_result.id}.pdf"'
    return response
