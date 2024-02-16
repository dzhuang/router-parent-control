from __future__ import annotations

from copy import deepcopy

from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from my_router.constants import DEFAULT_CACHE, days_const
from my_router.models import Device
from my_router.utils import CacheDataDoesNotExist, get_router_device_cache_key


class BoolToZeroOneField(serializers.Field):
    def to_internal_value(self, data):
        if isinstance(data, bool):
            return data

        msg = _("must be 0 or 1, while got {data}.").format(data=str(data))

        try:
            data = int(data)
        except ValueError:
            raise serializers.ValidationError(msg)
        else:
            if data not in [0, 1]:
                raise serializers.ValidationError(msg)

        return bool(data)

    def to_representation(self, value):
        return "1" if value else "0"


class MacAddressField(serializers.Field):
    def to_internal_value(self, data):
        return data.replace("-", ":")

    def to_representation(self, value):
        return value.replace(":", "-")


class LimitTimeSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        data["identifier"] = data.get("identifier", data.pop(".name", None))
        data["index_on_router"] = data.get(
            "index_on_router", data.pop(".index", None))
        return super().to_internal_value(data)

    identifier = serializers.CharField(max_length=255, required=True)
    index_on_router = serializers.IntegerField(min_value=1)
    name = serializers.CharField(max_length=255)

    mon = BoolToZeroOneField()
    tue = BoolToZeroOneField()
    wed = BoolToZeroOneField()
    thu = BoolToZeroOneField()
    fri = BoolToZeroOneField()
    sat = BoolToZeroOneField()
    sun = BoolToZeroOneField()

    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    apply_to = serializers.ListField(allow_empty=True)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        return ret


def split_name(s):
    s = s.strip()
    if not s:
        return []
    return s.split(",")


class DeviceModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["name", "mac", "known", "ignore", "added_datetime"]


class DeviceDataReverseSerializer(serializers.Serializer):
    def to_representation(self, data):
        data = super().to_representation(data)
        data["hostname"] = data.pop("name")
        data["limit_time"] = ",".join(data.pop("limit_time", []))
        data["forbid_domain"] = ",".join(data.pop("forbid_domain", []))
        data["blocked"] = data.pop("is_blocked")
        return data

    name = serializers.CharField(max_length=31)
    mac = MacAddressField()
    down_limit = serializers.IntegerField(default=0, min_value=0)
    up_limit = serializers.IntegerField(default=0, min_value=0)
    limit_time = serializers.ListField(allow_empty=True)
    forbid_domain = serializers.ListField(allow_empty=True)
    is_blocked = BoolToZeroOneField()


class DeviceJsonSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        data["index"] = int(data.pop("id", 0))
        data["name"] = data.get("name", data.pop("hostname"))
        data["is_blocked"] = data.pop("blocked") == "1"
        data["limit_time"] = split_name(data.get("limit_time", ""))
        data["forbid_domain"] = split_name(data.get("forbid_domain", ""))
        data["down_limit"] = int(data["down_limit"])
        data["up_limit"] = int(data["up_limit"])
        if data["is_blocked"] or data["ip"] == "0.0.0.0":
            data["online"] = False
        return super().to_internal_value(data)

    index = serializers.IntegerField(default=0)
    name = serializers.CharField(max_length=31)
    mac = MacAddressField()
    ignore = serializers.BooleanField(default=False)
    added_datetime = serializers.DateTimeField(default=now)
    down_limit = serializers.IntegerField(default=0, min_value=0)
    up_limit = serializers.IntegerField(default=0, min_value=0)
    limit_time = serializers.ListField(allow_empty=True)
    forbid_domain = serializers.ListField(allow_empty=True)
    is_blocked = serializers.BooleanField()
    up_speed = serializers.IntegerField(allow_null=True, default=0)
    down_speed = serializers.IntegerField(allow_null=True, default=0)
    acs_time = serializers.CharField(max_length=19, allow_null=True, required=False)
    online = serializers.BooleanField(allow_null=True, required=False, default=True)
    ip = serializers.IPAddressField(allow_null=True)


class ForbidDomainSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        data["identifier"] = data.get("identifier", data[".name"])
        data["index_on_router"] = data.get("index_on_router", data[".index"])
        return super().to_internal_value(data)

    identifier = serializers.CharField(max_length=255, required=True)
    index_on_router = serializers.IntegerField(min_value=1)
    domain = serializers.CharField(max_length=255, min_length=2)
    apply_to = serializers.ListField(allow_empty=True)


class InfoSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        data = deepcopy(data)
        for field in ["host_info", "forbid_domain", "limit_time"]:
            if field not in data:
                raise serializers.ValidationError(
                    {field: _("This field is required.")})

        limit_time_mac_dict = {}
        forbid_domain_mac_dict = {}

        for k, v in data["host_info"].items():
            serializer = DeviceJsonSerializer(data=v)
            serializer.is_valid()
            data["host_info"][k] = serializer.data
            for lm in serializer.data["limit_time"]:
                limit_time_mac_dict[lm] = list(set(
                    limit_time_mac_dict.get(lm, []) + [k]))

            for fd in serializer.data["forbid_domain"]:
                forbid_domain_mac_dict[fd] = list(set(
                    forbid_domain_mac_dict.get(fd, []) + [k]))

        for k, v in data["forbid_domain"].items():
            v["apply_to"] = forbid_domain_mac_dict.get(k, [])
            serializer = ForbidDomainSerializer(data=v)
            serializer.is_valid()
            data["forbid_domain"][k] = serializer.data

        for k, v in data["limit_time"].items():
            v["apply_to"] = limit_time_mac_dict.get(k, [])
            serializer = LimitTimeSerializer(data=v)
            serializer.is_valid()
            data["limit_time"][k] = serializer.data

        return super().to_internal_value(data)

    host_info = serializers.DictField(
        required=True, allow_empty=True, allow_null=True)

    forbid_domain = serializers.DictField(
        required=True, allow_empty=True, allow_null=True)

    limit_time = serializers.DictField(
        required=True, allow_empty=True, allow_null=True)

    def get_datatable_data(self, router, info_name):
        router_id = router.id
        data = deepcopy(self.data)
        host_info = data["host_info"]
        forbid_domain_data = data.get("forbid_domain", {})
        limit_time_data = data.get("limit_time", {})

        def get_device_dict_by_mac(_mac) -> dict:
            try:
                _device = Device.objects.get(router=router, mac=_mac)
            except Device.DoesNotExist:
                # device deleted from db accidentally
                return {}
            return {"name": host_info.get(_mac, {}).get("name", ""),
                    "url": reverse("device-edit", args=(router_id, _device.pk))}

        def get_rule_list(
                identifiers: list, _dict: dict, attribute_name,
                edit_url_name) -> list:
            _ret = []
            for identifier in identifiers:
                try:
                    _ret.append(
                        {"name": _dict[identifier].get(attribute_name, ""),
                         "url": reverse(
                             edit_url_name, args=(router_id, identifier))})
                except KeyError:
                    # happens when the limit_time or forbid_domain has been removed
                    continue

            return _ret

        ret = []
        if info_name == "device":
            for mac, value in host_info.items():
                value["forbid_domain"] = get_rule_list(
                    value.get("forbid_domain", ""), forbid_domain_data, "domain",
                    edit_url_name="forbid_domain-edit")
                value["limit_time"] = get_rule_list(
                    value.get("limit_time", ""), limit_time_data, "name",
                    edit_url_name="limit_time-edit")
                try:
                    device = Device.objects.get(mac=mac)
                    value["ignored"] = device.ignore
                    value["edit_url"] = reverse("device-edit",
                                                args=[router_id, device.id])
                except Device.DoesNotExist:
                    value["ignored"] = False
                    value["edit_url"] = None
                value["online"] = value.get("online", True)

                ret.append(value)

            ret = sorted(ret, key=lambda k: k["index"])

        elif info_name == "limit_time":
            for value in limit_time_data.values():
                for day in days_const.keys():
                    value[day] = True if int(value[day]) else False
                value["edit_url"] = reverse(
                    "limit_time-edit",
                    args=[router_id, value["identifier"]])
                value["delete_url"] = reverse(
                    "limit_time-delete",
                    args=[router_id, value["identifier"]])
                value["apply_to"] = [get_device_dict_by_mac(mac)
                                     for mac in value["apply_to"]]
                ret.append(value)

        else:
            assert info_name == "forbid_domain"
            for value in forbid_domain_data.values():
                value["edit_url"] = reverse("forbid_domain-edit",
                                            args=[router_id, value["identifier"]])
                value["delete_url"] = reverse("forbid_domain-delete",
                                            args=[router_id, value["identifier"]])
                value["apply_to"] = [get_device_dict_by_mac(mac)
                                     for mac in value["apply_to"]]

                ret.append(value)

        return ret

    def get_device_update_form_kwargs(self, router_id, mac):
        all_data = deepcopy(self.data)

        device_cached_data = DEFAULT_CACHE.get(
            get_router_device_cache_key(router_id, mac))
        if device_cached_data is None:
            raise CacheDataDoesNotExist()

        serializer = DeviceJsonSerializer(data=device_cached_data)
        assert serializer.is_valid(raise_exception=True)

        kwargs = {}

        for field_name in ["is_blocked", "down_limit", "up_limit"]:
            kwargs[field_name] = serializer.data[field_name]

        all_limit_times = all_data["limit_time"]
        kwargs["limit_time_choices"] = (
            tuple([v["identifier"], v["name"]]
                  for k, v in all_limit_times.items()))

        kwargs["limit_time_initial"] = list(
            v["identifier"] for k, v in all_limit_times.items()
            if k in serializer.data["limit_time"]
        )

        all_forbid_domains = all_data["forbid_domain"]
        kwargs["forbid_domain_choices"] = (
            tuple([v["identifier"], v["domain"]]
                  for k, v in all_forbid_domains.items()))

        kwargs["forbid_domain_initial"] = list(
            v["identifier"] for k, v in all_forbid_domains.items()
            if k in serializer.data["forbid_domain"]
        )

        return kwargs
