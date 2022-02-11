from __future__ import annotations

from collections.abc import Mapping

from django import forms

from my_router.constants import (CACHE_VERSION, DEFAULT_CACHE,
                                 DEVICE_CACHE_KEY_PATTERN,
                                 FORBID_DOMAINS_CACHE_KEY_PATTER,
                                 LIMIT_TIMES_CACHE_KEY_PATTER,
                                 ROUTER_DEVICE_MAC_ADDRESSES_CACHE_KEY_PATTERN,
                                 ROUTER_DEVICES_CACHE_KEY_PATTERN)


class StyledFormMixin:
    def __init__(self, *args, **kwargs):
        # type: (...) -> None
        from crispy_forms.helper import FormHelper
        self.helper = FormHelper()
        self._configure_helper()

        super().__init__(*args, **kwargs)

    def _configure_helper(self):
        # type: () -> None
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = "col-lg-2"
        self.helper.field_class = "col-lg-8"


class StyledForm(StyledFormMixin, forms.Form):
    pass


class StyledModelForm(StyledFormMixin, forms.ModelForm):
    pass


class ReadonlyDict(dict):
    # This is a read only dict, but key can be visit via attribute
    # https://stackoverflow.com/a/31049908/3437454
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e

    def __readonly__(self, *args, **kwargs):
        raise RuntimeError("Cannot modify ReadOnlyDict")

    __setattr__ = __readonly__
    __setitem__ = __readonly__
    __delattr__ = __readonly__
    pop = __readonly__
    popitem = __readonly__
    clear = __readonly__
    update = __readonly__
    setdefault = __readonly__
    del __readonly__


def deep_update(source, overrides):
    """
    Update a nested dictionary or similar mapping.
    Modify ``source`` in place.
    """
    for key, value in overrides.items():
        if isinstance(value, Mapping) and value:
            returned = deep_update(source.get(key, {}), value)
            source[key] = returned
        else:
            source[key] = overrides[key]
    return source


def get_device_cache_key(router_id, mac_address):
    return DEVICE_CACHE_KEY_PATTERN.format(
        router_id=router_id, mac_address=mac_address, cache_version=CACHE_VERSION)


def get_router_all_devices_mac_cache_key(router_id):
    return ROUTER_DEVICE_MAC_ADDRESSES_CACHE_KEY_PATTERN.format(
        router_id=router_id, cache_version=CACHE_VERSION)


def get_all_info_cache_key(router_id):
    return ROUTER_DEVICES_CACHE_KEY_PATTERN.format(
        router_id=router_id, cache_version=CACHE_VERSION)


def get_cached_limit_times_cache_key(router_id):
    return LIMIT_TIMES_CACHE_KEY_PATTER.format(
        router_id=router_id,
        cache_version=CACHE_VERSION)


def get_cached_forbid_domains_cache_key(router_id):
    return FORBID_DOMAINS_CACHE_KEY_PATTER.format(
        router_id=router_id,
        cache_version=CACHE_VERSION)


def get_cached_limit_times(router_id):
    return DEFAULT_CACHE.get(
        get_cached_limit_times_cache_key(router_id), None)


def get_cached_forbid_domains(router_id):
    return DEFAULT_CACHE.get(
        get_cached_forbid_domains_cache_key(router_id), None)
