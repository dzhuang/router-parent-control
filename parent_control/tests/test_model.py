from __future__ import annotations

from django.test import TestCase
from tests.data_for_tests import restructured_info_dicts1
from tests.mixins import CacheMixin, MockRouterClientMixin

from my_router.models import Device
from my_router.utils import (get_device_db_cache_key,
                             get_router_device_cache_key)
from my_router.views import fetch_new_info_save_and_set_cache


class DeviceTest(CacheMixin, MockRouterClientMixin, TestCase):
    def test_str(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(self.router.id)
        self.assertEqual(Device.objects.count(), 6)

        device1 = Device.objects.first()

        self.assertTrue(
            device1.router.name in str(device1) and device1.name in str(device1))

    def test_delete(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(self.router.id)
        self.assertEqual(Device.objects.count(), 6)

        device1 = Device.objects.first()

        self.assertEqual(
            self.test_cache.get(get_device_db_cache_key(device1.mac)),
            device1.name)

        self.assertIsNotNone(
            self.test_cache.get(
                get_router_device_cache_key(device1.router.id, device1.mac)))

        device1.delete()

        self.assertIsNone(self.test_cache.get(get_device_db_cache_key(device1.mac)))
        self.assertIsNone(
            self.test_cache.get(
                get_router_device_cache_key(device1.router.id, device1.mac)))
