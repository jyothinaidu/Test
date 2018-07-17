from django.conf.urls import url
from django.conf.urls import url, include

from . import views
from rest_framework_swagger.views import get_swagger_view

schema_view = get_swagger_view(title='Pastebin API')

urlpatterns = [
    url(r'^swagger/$', schema_view),

    url(r'^', include('rest_framework.urls', namespace='rest_framework')),

    url(r'^login/$',views.UserLoginAPIView.as_view(),name='login'),

    url(r'^register/$',views.UserRegistrationAPIView.as_view(),name='register'),

    url(r'^verify/(?P<verification_key>.+)/$',views.UserEmailVerificationAPIView.as_view(),name='email_verify'),

    url(r'^password_reset/$',views.PasswordResetAPIView.as_view(),name='password_change'),

    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.PasswordResetConfirmView.as_view(),
        name='password_reset_confirm'),

    url(r'^user-profile/$',views.UserProfileAPIView.as_view(),name='user_profile'),


]
