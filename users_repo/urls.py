from django.conf.urls import url, include
from django.contrib import admin
from accounts.api import views
urlpatterns = [

    url(r'^admin/', admin.site.urls),

    url(r'^api/users/', include('accounts.api.urls')),

    url(r'^$',views.home,name='login'),

    # url(r'^api/teams/', include('teams.api.urls')),
]
