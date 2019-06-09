import datetime

from django.shortcuts import render, redirect
from .models import User, ConfirmString
from .forms import UserForm, RegisterForm
from django.conf import settings
from django.http import JsonResponse
import hashlib


def index(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    return render(request, 'login/index.html')


def login(request):
    if request.session.get('is_login', None):  # 不允许重复登录
        return redirect("/index/")
    if request.method == "POST":
        login_form = UserForm(request.POST)
        message = '请检查填写的内容！'
        # print(username, password)
        if login_form.is_valid():
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')
            # 用户名验证，密码验证，其它验证
            try:
                user = User.objects.get(name=username)
            except:
                message = '用户不存在'
                return render(request, 'login/login.html', {'message': message, 'login_form': login_form})
            if not user.has_confirmed:
                message = '该用户还未经过邮件确认，请到邮箱点击链接确认'
                return render(request, 'login/login.html', locals())
            if user.password == hash_code(password):
                request.session['is_login'] = True
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                return redirect('/index/')
            else:
                message = '密码不正确'
                return render(request, 'login/login.html', {'message': message, 'login_form': login_form})
        else:
            return render(request, 'login/login.html', {'message': message, 'login_form': login_form})
    login_form = UserForm
    return render(request, 'login/login.html', {'login_form': login_form})


def register(request):
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        register_form = RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            gender = register_form.cleaned_data.get('gender')

            if password1 != password2:
                message = '两次输入的密码不同！'
                return render(request, 'login/register.html', {"message": message, "register_form": register_form})
            else:
                same_name_user = User.objects.filter(name=username)
                if same_name_user:
                    message = '用户名已经存在'
                    return render(request, 'login/register.html', {"message": message, "register_form": register_form})
                same_email_user = User.objects.filter(email=email)
                if same_email_user:
                    message = '该邮箱已经被注册了！'
                    return render(request, 'login/register.html', {"message": message, "register_form": register_form})

                new_user = User.objects.create(name=username, password=hash_code(password1), email=email, sex=gender)
                code = make_confirm_string(new_user)
                send_email(email, code)
                message = '请前往邮箱进行确认'
                return render(request, 'login/confirm.html', locals())
        else:
            return render(request, 'login/register.html', {"message": message, "register_form": register_form})
    register_form = RegisterForm()
    return render(request, 'login/register.html', {"register_form": register_form})


def user_confirm(request):
    code = request.GET.get('code', None)
    message = ''
    try:
        confirm = ConfirmString.objects.get(code=code)
    except:
        message = '无效的确认请求'
        return render(request, 'login/confirm.html', locals())

    c_time = confirm.c_time
    now = datetime.datetime.now()
    if now > c_time + datetime.timedelta(settings.CONFIRM_DAYS):
        confirm.user.delete()
        message = '您的邮件已经过期，请重新注册'
        return render(request, 'login/confirm.html', locals())
    else:
        confirm.user.has_confirmed = True
        confirm.user.save()
        confirm.delete()
        message = '请使用帐户登录！'
        return render(request, 'login/confirm.html', locals())


def logout(request):
    if not request.session.get('is_login', None):
        return redirect("/login/")
    request.session.flush()
    return redirect("/login/")


def hash_code(s, salt='mysite'):
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())  # update方法只接收bytes类型
    return h.hexdigest()


def make_confirm_string(user):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code = hash_code(user.name, now)
    ConfirmString.objects.create(code=code, user=user)
    return code


def send_email(email, code):
    from django.core.mail import EmailMultiAlternatives

    subject = '注册确认邮件'

    text_content = '''text_email_body'''

    html_content = '''
                    <p>点击<a href="http://{}/confirm/?code={}" target=blank>此处</a>激活</p>
                    <p>此链接有效期为{}天！</p>
                    '''.format('127.0.0.1:8000', code, settings.CONFIRM_DAYS)

    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()
