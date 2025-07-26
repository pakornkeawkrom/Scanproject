from django.urls import path
from . import views

app_name = 'scp4' 

urlpatterns = [
    path('index/', views.index, name='index'), 
    path('', views.home, name='home'), 
    path('signup/', views.signup_view, name='signup'),
    path('analyze_code/', views.analyze_code_api, name='analyze_code_api'),
    path('scan_result/<int:scan_result_id>/', views.view_scan_result, name='view_scan_result'),
    path('scan_result/<int:scan_result_id>/pdf/', views.export_scan_report_pdf, name='export_scan_report_pdf'),
    path('clear_scan_history/', views.clear_scan_history, name='clear_scan_history'),
    path('delete_selected_scans/', views.delete_selected_scans, name='delete_selected_scans'),

]