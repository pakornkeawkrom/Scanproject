from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=30, 
        required=False, 
        help_text='ชื่อจริง (ไม่บังคับ)',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'ชื่อจริง'
        })
    )
    last_name = forms.CharField(
        max_length=30, 
        required=False, 
        help_text='นามสกุล (ไม่บังคับ)',
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'นามสกุล'
        })
    )
    email = forms.EmailField(
        required=True,
        help_text='อีเมลสำหรับติดต่อ',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'อีเมล'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    # ใช้ข้อความธรรมดาแทน HTML
        self.fields['password1'].help_text = (
            "• รหัสผ่านไม่ควรคล้ายกับข้อมูลส่วนตัวของคุณมากเกินไป\n"
            "• รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร\n" 
            "• รหัสผ่านไม่ควรเป็นรหัสผ่านที่ใช้กันทั่วไป\n"
            "• รหัสผ่านไม่ควรเป็นตัวเลขเพียงอย่างเดียว"
        )
    
        self.fields['password2'].help_text = 'ใส่รหัสผ่านเดิมอีกครั้งเพื่อยืนยัน'
    
    # เพิ่ม CSS class และ placeholder
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'รหัสผ่าน'
        })
    
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'ยืนยันรหัสผ่าน'
        })

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'ชื่อผู้ใช้'
            })
        }

    def clean_email(self):
        """ตรวจสอบว่า email ซ้ำหรือไม่"""
        email = self.cleaned_data.get('email')
        
        if not email:
            raise ValidationError("กรุณาใส่อีเมล")
            
        # ตรวจสอบอีเมลซ้ำ
        if User.objects.filter(email=email).exists():
            raise ValidationError("อีเมลนี้ถูกใช้แล้ว กรุณาใช้อีเมลอื่น")
            
        return email

    def clean_username(self):
        """ตรวจสอบชื่อผู้ใช้"""
        username = self.cleaned_data.get('username')
        
        if len(username) < 3:
            raise ValidationError("ชื่อผู้ใช้ต้องมีอย่างน้อย 3 ตัวอักษร")
            
        if User.objects.filter(username=username).exists():
            raise ValidationError("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
            
        return username

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        
        if commit:
            user.save()
        return user