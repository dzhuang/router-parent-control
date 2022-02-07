from django.contrib import admin
from django.forms import ModelForm, PasswordInput

from my_router.models import Device, Router


class RouterForm(ModelForm):
    class Meta:
        model = Router
        fields = "__all__"
        widgets = {
            'admin_password': PasswordInput(),
        }


class RouterAdmin(admin.ModelAdmin):
    form = RouterForm
    save_on_top = True


admin.site.register(Router, RouterAdmin)


class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "mac_address",
        "name",
        "router",
        "ignore",
        "known",
    )
    list_editable = (
        "name",
        "ignore",
    )
    list_filter = (
        "ignore",
        "known",
    )
    save_on_top = True


admin.site.register(Device, DeviceAdmin)
