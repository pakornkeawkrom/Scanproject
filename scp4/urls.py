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
    path('history/', views.scan_history, name='scan_history'),  # เพิ่มหน้าประวัติ
    path('history/delete/<int:result_id>/', views.delete_scan_result, name='delete_scan_result'),
    path('profile/', views.profile, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('profile/export-data/', views.export_all_data, name='export_all_data'),
    path('profile/delete-account/', views.delete_account, name='delete_account'),
    
    # Custom Admin Panel
    path('custom-admin/', views.custom_admin, name='custom_admin'),
    path('custom-admin/users/', views.admin_users, name='admin_users'),
    path('custom-admin/scans/', views.admin_scans, name='admin_scans'),
    path('custom-admin/system/', views.admin_system, name='admin_system'),
]