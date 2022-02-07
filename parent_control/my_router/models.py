from django.db import models
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from pyrouter.router_client import RouterClient

from my_router.fields import MACAddressField


class Router(models.Model):
    identifier = models.CharField(max_length=255, unique=True, blank=False)
    name = models.CharField(max_length=255, verbose_name=_("Router name"))
    description = models.CharField(max_length=255, null=True)
    url = models.URLField(null=False, help_text=_("The URL of the router"))
    admin_password = models.CharField(
        null=False, max_length=255)

    # todo: allow select api by model
    model = models.CharField(
        max_length=255, verbose_name=_("Router model"), blank=True)

    def __str__(self):
        return self.name

    def get_client(self):
        return RouterClient(url=self.url, password=self.admin_password)


class Device(models.Model):
    name = models.CharField(max_length=31, blank=False)
    mac_address = MACAddressField(blank=False, db_index=True)
    router = models.ForeignKey(Router, on_delete=models.CASCADE)
    known = models.BooleanField(
        default=False, help_text=_("This devices is known."))
    ignore = models.BooleanField(
        default=False, help_text=_(
            "This device will be ignored when listing and bulk applying "
            "limit time or forbid domain constraints."))
    added_datetime = models.DateTimeField(
        default=now, verbose_name=_("Added datetime"))

    class Meta:
        unique_together = ("router", "mac_address")

    def save(self, *args, **kwargs):
        # Don't save object if no field changes.
        # Get updated_fields: https://stackoverflow.com/a/55005137/3437454
        if self.pk:
            # If self.pk is not None then it's an update.
            cls = self.__class__

            # This will get the current model state since super().save()
            # isn't called yet.
            old = cls.objects.get(pk=self.pk)

            # This gets the newly instantiated Mode object with the new values.
            new = self
            changed_fields = []
            for field in cls._meta.get_fields():
                field_name = field.name
                try:
                    if getattr(old, field_name) != getattr(new, field_name):
                        changed_fields.append(field_name)
                except Exception:
                    # Catch field does not exist exception
                    pass
            kwargs['update_fields'] = changed_fields
        super().save(*args, **kwargs)

    def __str__(self):
        return _("{device} on {router}").format(
            device=self.name, router=self.router.name)

    def get_absolute_url(self):
        return reverse("device-edit", args=(self.router.pk, self.pk,))
