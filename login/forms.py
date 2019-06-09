from django import forms
from captcha.fields import CaptchaField

class UserForm(forms.Form):
    username = forms.CharField(label="用户名", max_length=128,
                               widget=forms.TextInput(attrs={'placeholder': "username", 'autofocus': ''}))
    password = forms.CharField(label="密码", max_length=256,
                               widget=forms.PasswordInput(attrs={'placeholder': 'password'}))
    captcha=CaptchaField(label="验证码")

class RegisterForm(forms.Form):
    genders=(('male',"男"),('famale','女'))
    username=forms.CharField(label="用户名",max_length=128,
                             widget=forms.TextInput(attrs={'placeholder':"username","autofocus":''}))
    password1=forms.CharField(label="密码",max_length=256,
                             widget=forms.PasswordInput(attrs={"class":"form-control","placeholder":'password'}))
    password2=forms.CharField(label="重复密码",max_length=256,
                             widget=forms.PasswordInput(attrs={"class":"form-control","placeholder":'password again'}))
    email=forms.EmailField(label="邮箱",max_length=128,widget=forms.EmailInput(attrs={'placeholder':'例如123@qq.com'}))
    gender=forms.ChoiceField(label="性别",choices=genders)
    captcha=CaptchaField(label="验证码")