from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login,  logout
from gfg import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from email.message import EmailMessage


def home(request):
    return render(request, 'base/index.html')

def signup(request):

    if request.method == "POST":
        #username = request.POST.get('username', )
        username = request.POST['username']
        firstname = request.POST['first name']
        lastname = request.POST['last name']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try someother username")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request, "Email already registered!")
            return redirect('home')

        if len(username)>10:
            messages.error(request, "Username must not be under 10 characters")

        if password1 != password2:
            messages.error(request, "Passwords didn't match!")

        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!")
            return redirect('home')    

        myuser = User.objects.create_user(username, email, password1,)
        myuser.first_name = firstname
        myuser.lastname_name = lastname
        myuser.is_active =  False
        myuser.save()

        messages.success(request, "Your Account has been successfully created.we have sent you a confirmation email, please confirm your email to activate your account ")



        # Welcome

        subject = "Welcome to GFG - Django Login!!"
        message = "Hello " + myuser.first_name + "!! \n"+ "Welcome to GFG!! \n Thank you for visting our website \n We have also sent a you  a confirmation email, please confirm your email address in order to activate your account \n Thank You "
        from_email = settings.EMAIL_HOST_USER
        to_list =[myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True )
    
        # Email Address confirmation email

        current_site = get_current_site(request)
        email_subject = "Confirm your email @ GFG - Gjango!!"
        message2 = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            "uid": urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = True
        email.send()


        
        return redirect('signin')


    return render(request, 'base/signup.html') 

def signin(request):

    if request.method == 'POST':
        username = request.POST['username']
        password1 = request.POST['password1']

        user = authenticate(username=username, password=password1)

        if user is not None:
            login(request, user)
            firstname = user.first_name
            return render(request, "base/index.html", {'firstname': firstname} )

        else:
            messages.error(request, "Bad Credentials!")    
            return redirect('home')


    return render(request, 'base/signin.html')    

def signout(request):
    logout(request)
    messages.success(request, "Logged Out successfully ")
    return redirect('home')

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_encode(uidb64))
        myuser= User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
    else:
        return render(request, 'activation_failed.html')


         
