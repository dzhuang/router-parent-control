from __future__ import annotations

from copy import deepcopy

from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from my_router.models import Device, Router


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

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        return ret


def convert_strings_to_identifier_list(s):
    s = s.strip()
    if not s:
        return []
    identifiers = [_s.strip() for _s in s.split(",")]
    return list(dict(identifier=i) for i in identifiers)


class DeviceModelSerializer(serializers.ModelSerializer):
    def to_internal_value(self, data):
        data["mac_address"] = data.get("mac_address", data.pop("mac"))
        data["name"] = data.get("name", data.pop("hostname"))
        data["is_blocked"] = data.get("is_blocked", data.pop("blocked"))

        return super().to_internal_value(data)

    class Meta:
        model = Device
        fields = ["name", "mac_address", "added_datetime"]


class DeviceSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        data["mac_address"] = data.get("mac_address", data.pop("mac"))
        data["name"] = data.get("name", data.pop("hostname"))
        data["is_blocked"] = data.get("is_blocked", data.pop("blocked"))

        return super().to_internal_value(data)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["mac"] = ret.pop("mac_address")
        ret["limit_time"] = convert_strings_to_identifier_list(
            ret.get("limit_time", ""))
        ret["forbid_domain"] = convert_strings_to_identifier_list(
            ret.get("forbid_domain", ""))
        ret["down_limit"] = int(ret["down_limit"])
        ret["up_limit"] = int(ret["up_limit"])
        return ret

    name = serializers.CharField(max_length=255)
    mac_address = MacAddressField()
    ignore = serializers.BooleanField(default=False)
    added_datetime = serializers.DateTimeField(default=now)
    down_limit = serializers.CharField(default="0")
    up_limit = serializers.CharField(default="0")
    limit_time = serializers.CharField(
        max_length=255, default="", allow_blank=True)
    forbid_domain = serializers.CharField(
        max_length=255, default="", allow_blank=True)
    is_blocked = BoolToZeroOneField()


class ForbidDomainSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        data["identifier"] = data.get("identifier", data.pop(".name", None))
        data["index_on_router"] = data.get(
            "index_on_router", data.pop(".index", None))
        return super().to_internal_value(data)

    identifier = serializers.CharField(max_length=255, required=True)
    index_on_router = serializers.IntegerField(min_value=1)
    domain = serializers.CharField(max_length=255, min_length=2)


class InfoSerializer(serializers.Serializer):
    host_info = serializers.DictField(
        required=False, child=serializers.DictField(), allow_empty=False)

    forbid_domain = serializers.DictField(
        required=False, child=serializers.DictField(), allow_empty=False)

    limit_time = serializers.DictField(
        required=False, child=serializers.DictField(), allow_empty=False)

    def get_datatable_data(self, router_id, info_name):
        data = deepcopy(self.data)
        host_info = data["host_info"]
        forbid_domain_data = data.get("forbid_domain", {})
        limit_time_data = data.get("limit_time", {})

        def get_device_dict_name_by_mac(_mac) -> dict:
            router = Router.objects.get(id=router_id)
            try:
                _device = Device.objects.get(router=router, mac_address=_mac)
            except Device.DoesNotExist:
                return {}
            return {"name": host_info.get(_mac, {}).get("hostname", ""),
                    "url": reverse("device-edit", args=(router_id, _device.pk))}

        def get_rule_list(
                identifiers_str: str, _dict: dict, attribute_name,
                edit_url_name) -> list:
            identifiers_str = identifiers_str.strip()
            if not identifiers_str:
                return []
            _ret = []
            identifiers = identifiers_str.split(",")
            for identifier in identifiers:
                _ret.append(
                    {"name": _dict[identifier].get(attribute_name, ""),
                     "url": reverse(edit_url_name, args=(router_id, identifier,))})

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
                    device = Device.objects.get(mac_address=mac)
                    value["ignored"] = device.ignore
                    value["edit-url"] = reverse("device-edit",
                                                args=[router_id, device.id])
                except Device.DoesNotExist:
                    value["ignored"] = False
                    value["edit-url"] = None
                value["is_blocked"] = True if value["blocked"] == "1" else False
                value["id"] = int(value.get("id", "0"))
                value["online"] = value.get("online", True)
                if value["is_blocked"]:
                    value["online"] = False

                ret.append(
                    [value["id"], value["hostname"], value["edit-url"],
                     value["mac"],
                     value.get("acs_time", ""), value["online"], value["ip"],
                     value["is_blocked"],
                     value["down_limit"],
                     value["up_limit"],
                     value["limit_time"],
                     value["forbid_domain"],
                     value["ignored"]])

            ret = sorted(ret, key=lambda k: k[0])

        elif info_name == "limit_time":
            for value in limit_time_data.values():
                for day in ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]:
                    value[day] = True if int(value[day]) else False
                value["edit_url"] = reverse("limit_time-edit",
                                            args=[router_id, value[".name"]])
                value["apply_to"] = [get_device_dict_name_by_mac(mac)
                                     for mac in value["apply_to"]]

                ret.append([
                    value[".index"],
                    value["name"],
                    value["edit_url"],
                    value["start_time"],
                    value["end_time"],
                    value["mon"], value["tue"], value["wed"], value["thu"],
                    value["fri"],
                    value["sat"], value["sun"],
                    value["apply_to"]
                ])

        else:
            assert info_name == "forbid_domain"
            for value in forbid_domain_data.values():
                value["edit_url"] = reverse("forbid_domain-edit",
                                            args=[router_id, value[".name"]])
                value["apply_to"] = [get_device_dict_name_by_mac(mac)
                                     for mac in value["apply_to"]]

                ret.append([
                    value[".index"],
                    value["domain"],
                    value["edit_url"],
                    value["apply_to"]
                ])

        return ret
