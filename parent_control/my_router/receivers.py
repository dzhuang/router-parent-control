from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

from my_router.constants import router_status
from my_router.models import Device, Router
from my_router.utils import DEFAULT_CACHE, get_router_device_cache_key
from my_router.views import fetch_new_info_save_and_set_cache


@receiver(post_save, sender=get_user_model())
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=Router)
def create_or_update_router_fetch_task(sender, instance: Router, created, **kwargs):
    if created:
        instance.setup_task()
        fetch_new_info_save_and_set_cache(instance.id)
    else:
        if instance.task is not None:
            instance.task.enabled = instance.status == router_status.active
            instance.task.save()


@receiver(post_save, sender=Device)
def cache_device_info_after_save(sender, instance: Device, **kwargs):
    instance.update_cache()


@receiver(post_delete, sender=Device)
def remove_device_cache_after_delete(sender, instance: Device, **kwargs):
    DEFAULT_CACHE.delete(
        get_router_device_cache_key(instance.router_id, instance.mac))
    fetch_new_info_save_and_set_cache(instance.id)
