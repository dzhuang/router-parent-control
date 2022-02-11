import django.core.cache as cache
from django.utils.translation import gettext_lazy as _

CACHE_VERSION = 2
DEFAULT_CACHE = cache.caches["default"]

ROUTER_DEVICES_CACHE_KEY_PATTERN = "router-instance:{router_id}{cache_version}"
LIMIT_TIMES_CACHE_KEY_PATTER = "limit_time:{router_id}:{cache_version}"
FORBID_DOMAINS_CACHE_KEY_PATTER = "forbid_domain:{router_id}:{cache_version}"

ROUTER_DEVICE_MAC_ADDRESSES_CACHE_KEY_PATTERN = (
    "{router_id}:mac_addresses:{cache_version}")
DEVICE_CACHE_KEY_PATTERN = "{router_id}:device:{mac}{cache_version}"


class router_status:  # noqa
    active = "active"
    disabled = "disabled"


ROUTER_STATUS_CHOICES = (
    (router_status.active, _("Active")),
    (router_status.disabled, _("Disabled")),
)
