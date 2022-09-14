from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path
from django.utils.translation import gettext_lazy as _

from my_router import auth, views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(
        redirect_authenticated_user=True,
        template_name='generic-form-page.html',
        form_class=auth.AuthenticationForm,
        extra_context={"form_description": _("Sign in")}),
         name='login'),
    path('logout/', auth_views.LogoutView.as_view(
        template_name='registration/logged_out.html'),
         name='logout'),
    path('profile', auth.user_profile, name='profile'),
    path('', views.home, name='home'),

    path('router/<router_id>/<info_name>/ajax/', views.fetch_cached_info,
         name="fetch-cached-info"),

    path('router/<router_id>/devices/', views.list_devices,
         name="device-list"),
    path('router/<router_id>/device/<pk>/update',
         views.DeviceUpdateView.as_view(), name="device-edit"),

    path('router/<router_id>/limit_time/list/', views.list_limit_time,
         name="limit_time-list"),
    path('router/<router_id>/limit_time/<limit_time_name>/edit/',
         views.edit_limit_time, name="limit_time-edit"),
    path('router/<router_id>/limit_time/<limit_time_name>/delete/',
         views.delete_limit_time, name="limit_time-delete"),

    path('router/<router_id>/forbid_domain/list/', views.list_forbid_domain,
         name="forbid_domain-list"),
    path('router/<router_id>/forbid_domain/<forbid_domain_name>/edit/',
         views.edit_forbid_domain, name="forbid_domain-edit"),
    path('router/<router_id>/forbid_domain/<forbid_domain_name>/delete/',
         views.delete_forbid_domain, name="forbid_domain-delete"),

    path('router/<router_id>/reboot/',
         views.reboot_router, name="router-reboot"),
]
