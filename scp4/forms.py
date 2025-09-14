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