import django.core.cache as cache

CACHE_VERSION = 1
DEFAULT_CACHE = cache.caches["default"]

ROUTER_DEVICES_CACHE_KEY_PATTERN = "router-instance:{router_id}{cache_version}"
LIMIT_TIMES_CACHE_KEY_PATTER = "limit_time:{router_id}:{cache_version}"
FORBID_DOMAINS_CACHE_KEY_PATTER = "forbid_domain:{router_id}:{cache_version}"

ROUTER_DEVICE_MAC_ADDRESSES_CACHE_KEY_PATTERN = (
    "{router_id}:mac_addresses:{cache_version}")
DEVICE_CACHE_KEY_PATTERN = "device:{mac_address}{cache_version}"
