from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='จำเป็นต้องใช้ Email ที่ถูกต้อง', label='อีเมล')

    class Meta(UserCreationForm.Meta): 
        model = User
        fields = ('username', 'email') 
        
        labels = {
            'username': 'ชื่อผู้ใช้งาน',
            'email': 'อีเมล',
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user