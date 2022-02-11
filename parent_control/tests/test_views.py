from __future__ import annotations

from copy import deepcopy
from unittest import mock

from crispy_forms.layout import Submit
from django.test import TestCase
from django.urls import reverse
from tests.data_for_tests import (restructured_info_dicts1,
                                  restructured_info_dicts2)
from tests.factories import RouterFactory
from tests.mixins import CacheMixin, MockAddMessageMixing, RequestTestMixin

from my_router.models import Device
from my_router.utils import (DEFAULT_CACHE,
                             get_cached_forbid_domains_cache_key,
                             get_cached_limit_times_cache_key,
                             get_device_cache_key)
from my_router.views import (fetch_new_info_and_cache,
                             get_all_cached_info_with_online_status)


class MockRouterClientMixin:
    def setUp(self):
        super().setUp()

        with mock.patch(
                "my_router.receivers.fetch_new_info_and_cache"
        ) as mock_fetch_and_cache:
            mock_fetch_and_cache.return_value = None
            self.router = RouterFactory()

        get_restructured_info_dicts_patch = mock.patch(
            "my_router.models.RouterClient.get_restructured_info_dicts")
        self.mock_get_restructured_info_dicts = (
            get_restructured_info_dicts_patch.start())
        self.addCleanup(get_restructured_info_dicts_patch.stop)

        set_host_info_patch = mock.patch(
            "my_router.models.RouterClient.set_host_info")
        self.mock_set_host_info = set_host_info_patch.start()
        self.addCleanup(set_host_info_patch.stop)

    def set_get_restructured_info_dicts_ret(self, result):
        # mock client.get_restructured_info_dicts return_value
        self.mock_get_restructured_info_dicts.return_value = result

    def set_get_restructured_info_dicts_side_effect(self, func=lambda x: None):
        # mock client.get_restructured_info_dicts side_effect
        self.mock_get_restructured_info_dicts.side_effect = func  # noqa

    def set_set_host_info_side_effect(self, func=lambda x: None):
        # mock client.set_host_info
        self.mock_set_host_info.side_effect = func  # noqa

    def fetch_cached_info_url(self, info_name="device", router_id=None):
        router_id = router_id or self.router.id
        return reverse("fetch-cached-info", args=(router_id, info_name,))


class FetchNewInfoAndCacheTest(MockRouterClientMixin, CacheMixin, TestCase):
    device_1_cached_value = {
        'blocked': '0',
        'down_limit': '0',
        'down_speed': '0',
        'forbid_domain': '',
        'hostname': 'CONTROL_HOST',
        'ip': '192.168.0.119',
        'is_cur_host': '1',
        'limit_time': '',
        'mac': '00-11-22-33-44-55',
        'plan_rule': [],
        'type': '0',
        'up_limit': '0',
        'up_speed': '0'}

    device_1_cached_value_changed = {
        'blocked': '0',
        'down_limit': '0',
        'down_speed': '0',
        'forbid_domain': '',
        'hostname': 'CONTROL_HOST',
        'ip': '192.168.0.129',
        'is_cur_host': '1',
        'limit_time': '',
        'mac': '00-11-22-33-44-55',
        'plan_rule': [],
        'type': '0',
        'up_limit': '0',
        'up_speed': '0'}

    def test_ok(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)
        self.assertDictEqual(
            DEFAULT_CACHE.get(
                get_device_cache_key(self.router.id, "00-11-22-33-44-55")),
            self.device_1_cached_value
        )

    def test_device_cache_deleted(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)

        self.assertDictEqual(
            DEFAULT_CACHE.get(
                get_device_cache_key(self.router.id, "00-11-22-33-44-55")),
            self.device_1_cached_value
        )

        self.assertEqual(
            DEFAULT_CACHE.get(
                get_cached_limit_times_cache_key(
                    self.router.id))["limit_time_4"]["apply_to"],
            []
        )
        self.assertEqual(
            DEFAULT_CACHE.get(
                get_cached_forbid_domains_cache_key(
                    self.router.id))["forbid_domain_3"]["apply_to"],
            ['33-33-33-33-33-33']
        )

        # Remove the cache of a device not in dicts1
        DEFAULT_CACHE.delete(
            get_device_cache_key(self.router.id, "44-44-44-44-44-44"))

        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_and_cache(self.router.id)

        self.assertDictEqual(
            DEFAULT_CACHE.get(
                get_device_cache_key(self.router.id, "00-11-22-33-44-55")),
            self.device_1_cached_value_changed
        )
        self.assertEqual(
            DEFAULT_CACHE.get(
                get_cached_limit_times_cache_key(
                    self.router.id))["limit_time_4"]["apply_to"],
            ["55-55-55-55-55-55"]
        )
        self.assertEqual(
            sorted(DEFAULT_CACHE.get(
                get_cached_forbid_domains_cache_key(
                    self.router.id))["forbid_domain_3"]["apply_to"]),
            ['33-33-33-33-33-33', "55-55-55-55-55-55"]
        )

    def test_no_router(self):
        self.router.delete()
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)


class GetAllCachedInfoWithOnlineStatusTest(
        MockRouterClientMixin, CacheMixin, TestCase):
    # test views.get_all_cached_info_with_online_status
    def test_fetched_new_info(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)

        # No fetch_new_info_and_cache called to test cache_info is None
        info = get_all_cached_info_with_online_status(self.router.id)
        host_info_44 = info["host_info"]["44-44-44-44-44-44"]
        with self.assertRaises(KeyError):
            host_info_44["online"]  # noqa
        self.assertEqual(host_info_44["limit_time"], "limit_time_1,limit_time_3")
        self.assertEqual(host_info_44["forbid_domain"], "forbid_domain_1")

        # new info fetched
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_and_cache(self.router.id)
        info = get_all_cached_info_with_online_status(self.router.id)

        host_info_44 = info["host_info"]["44-44-44-44-44-44"]
        self.assertFalse(host_info_44["online"])

        # limit_time_1 and forbid_domain_1 is removed
        self.assertEqual(host_info_44["limit_time"], "limit_time_3")
        self.assertEqual(host_info_44["forbid_domain"], "")

    def test_device_cache_deleted(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)

        # new info fetched
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_and_cache(self.router.id)

        # Remove the cache of a device not in dicts1
        DEFAULT_CACHE.delete(
            get_device_cache_key(self.router.id, "44-44-44-44-44-44"))

        info = get_all_cached_info_with_online_status(self.router.id)
        self.assertNotIn("44-44-44-44-44-44", info["host_info"])


class ListDevicesTest(RequestTestMixin, MockRouterClientMixin, CacheMixin, TestCase):
    def device_list_url(self):
        return reverse("device-list", args=(self.router.id,))

    def test_get_ok(self):
        resp = self.client.get(self.device_list_url())
        self.assertEqual(resp.status_code, 200)

    def test_login_required(self):
        self.client.logout()
        resp = self.client.get(self.device_list_url())
        self.assertEqual(resp.status_code, 302)


class FetchCachedInfoTest(
        RequestTestMixin, MockRouterClientMixin, CacheMixin, TestCase):

    def test_post_forbidden(self):
        for info_name in ["device", "limit_time", "forbid_domain"]:
            resp = self.client.post(
                self.fetch_cached_info_url(info_name=info_name), data={})
        self.assertEqual(resp.status_code, 403)

    def test_cached_info_invalid(self):
        for info_name in ["device", "limit_time", "forbid_domain"]:
            with mock.patch(
                    "my_router.views.get_all_cached_info_with_online_status"
            ) as patch_get_cached_info:
                patch_get_cached_info.return_value = {"foo": "bar"}
                resp = self.client.get(
                    self.fetch_cached_info_url(info_name=info_name))
        self.assertEqual(resp.status_code, 400)

    def test_cached_info_None(self):
        for info_name in ["device", "limit_time", "forbid_domain"]:
            with mock.patch(
                    "my_router.views.get_all_cached_info_with_online_status"
            ) as patch_get_cached_info:
                patch_get_cached_info.return_value = None
                resp = self.client.get(
                    self.fetch_cached_info_url(info_name=info_name))
        self.assertEqual(resp.status_code, 200)

    def fetch_2_info(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)

        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_and_cache(self.router.id)

    def test_fetch_cached_device_info(self):
        self.fetch_2_info()
        resp = self.client.get(self.fetch_cached_info_url())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Device.objects.count(), 7)
        result = resp.json()
        for device_result in result:
            (_id, hostname, edit_url, mac, asc_time, online, ip, is_blocked,
             down_limit, up_limit, limit_time, forbid_domain, ignored
             ) = device_result

            if hostname in ["BLOCKED_DEVICE1", "BLOCKED_DEVICE2", "LIMITED_HOST2"]:
                self.assertFalse(online)
            else:
                self.assertTrue(online, hostname)

            if hostname in ["BLOCKED_DEVICE1", "BLOCKED_DEVICE2"]:
                self.assertTrue(is_blocked)
            else:
                self.assertFalse(is_blocked, hostname)

            if hostname in ["LIMITED_HOST1", "ANOTHER_HOST"]:
                self.assertTrue(len(forbid_domain) > 0)
            else:
                self.assertEqual(forbid_domain, [])

            if hostname in ["LIMITED_HOST2", "ANOTHER_HOST"]:
                self.assertTrue(len(limit_time) > 0)
            else:
                self.assertEqual(limit_time, [])

    def test_fetch_cached_device_info_twice(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)
        resp = self.client.get(self.fetch_cached_info_url())
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(Device.objects.count(), 6)

        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_and_cache(self.router.id)
        resp = self.client.get(self.fetch_cached_info_url())
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(Device.objects.count(), 7)

    def test_fetch_cached_limit_time_info(self):
        self.fetch_2_info()
        resp = self.client.get(self.fetch_cached_info_url(info_name="limit_time"))
        self.assertEqual(resp.status_code, 200)
        for limit_time_result in resp.json():
            (index, name, edit_url, start_time, end_time, mon,
             tue, wed, thu, fri, sat, sun, apply_to) = limit_time_result
            if index in [22, 25]:
                self.assertEqual(len(apply_to), 1)
            else:
                self.assertEqual(len(apply_to), 0)

    def test_fetch_cached_forbid_domain_info(self):
        self.fetch_2_info()
        resp = self.client.get(self.fetch_cached_info_url(info_name="forbid_domain"))
        self.assertEqual(resp.status_code, 200)
        for forbid_domain_result in resp.json():

            index, domain, edit_url, apply_to = forbid_domain_result
            if index in [23, 30]:
                self.assertEqual(len(apply_to), 1)
            elif index == 29:
                self.assertEqual(len(apply_to), 2)
            else:
                self.assertEqual(len(apply_to), 0)


class DeviceUpdateViewTest(
        RequestTestMixin, MockRouterClientMixin, MockAddMessageMixing,
        CacheMixin, TestCase):

    def setUp(self):
        super().setUp()
        refresh_all_info_cache_patch = mock.patch(
            "my_router.views.DeviceUpdateView.refresh_all_info_cache")
        self.mock_refresh_info_cache = refresh_all_info_cache_patch.start()
        self.addCleanup(refresh_all_info_cache_patch.stop)

    def device_edit_url(self, device_pk, router_id=None):
        router_id = router_id or self.router.pk
        return reverse("device-edit", args=(router_id, device_pk))

    def test_login_required(self):
        self.client.logout()
        resp = self.client.get(self.device_edit_url(device_pk=1))
        self.assertEqual(resp.status_code, 302)

    def test_get_ok(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)

        # This step is need, user should first view the list page before edit
        self.client.get(self.fetch_cached_info_url())

        for pk in Device.objects.all().values_list("pk", flat=True):
            resp = self.client.get(
                self.device_edit_url(device_pk=pk)
            )

            self.assertEqual(resp.status_code, 200)
            form = self.get_response_context_value_by_name(resp, "form")
            self.assertIsInstance(form.helper.inputs[0], Submit)

    def test_get_fetch_fail(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)
        self.client.get(self.fetch_cached_info_url())

        def fail():
            raise RuntimeError("foo bar")

        self.set_get_restructured_info_dicts_side_effect(fail)

        resp = self.client.get(self.device_edit_url(device_pk=1))

        self.assertEqual(resp.status_code, 200)
        self.assertAddMessageCallCount(1)

        form = self.get_response_context_value_by_name(resp, "form")

        # no submit button
        self.assertEqual(form.helper.inputs, [])

    def set_test_device_instance(self, mac=None) -> (Device, dict):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_and_cache(self.router.id)
        self.client.get(self.fetch_cached_info_url())
        assert Device.objects.count() == 6
        mac = mac or "22-33-44-55-66-77"
        instance: Device = Device.objects.get(mac=mac)
        data: dict = restructured_info_dicts1["host_info"][mac]
        return instance, data

    def get_instance_and_post_data(self, mac=None, **kwargs) -> (Device, dict):
        instance, data = self.set_test_device_instance(mac)
        data = deepcopy(data)
        limit_time: list | str = data.get("limit_time", "") or []
        if limit_time:
            limit_time: list = limit_time.split(",")

        forbid_domain: list | str = data.get("forbid_domain", "") or []
        if forbid_domain:
            forbid_domain: list = forbid_domain.split(",")

        post_data = {
            "name": instance.name,
            "ignore": instance.ignore,
            "is_blocked": data.get("blocked") == "1",
            "down_limit": data["down_limit"],
            "up_limit": data["up_limit"],
            "limit_time": limit_time,
            "forbid_domain": forbid_domain,
            "submit": []
        }

        post_data.update(**kwargs)
        return instance, post_data

    def test_post_no_change_ok(self):
        instance, post_data = self.get_instance_and_post_data()

        with mock.patch("my_router.models.models.Model.save") as mock_super_save:
            resp = self.client.post(
                self.device_edit_url(instance.pk), data=post_data)
            self.assertEqual(resp.status_code, 302)
            self.mock_set_host_info.assert_not_called()

            # instance is not updated
            mock_super_save.assert_not_called()
            self.mock_refresh_info_cache.assert_not_called()

    def test_post_saved_to_db_no_remote_operation_ok(self):
        for model_field in ["ignore", "known"]:
            kwargs = {model_field: True}
            instance, post_data = self.get_instance_and_post_data(**kwargs)

            with mock.patch("my_router.models.models.Model.save") as mock_super_save:
                resp = self.client.post(
                    self.device_edit_url(instance.pk), data=post_data)
                self.assertEqual(resp.status_code, 302)
                self.mock_set_host_info.assert_not_called()

                # instance updated
                mock_super_save.assert_called_once_with(update_fields=[model_field])
                self.mock_refresh_info_cache.assert_not_called()

    def test_post_change_name_ok(self):
        new_name = "foobar"
        instance, post_data = self.get_instance_and_post_data(name=new_name)

        resp = self.client.post(
            self.device_edit_url(instance.pk), data=post_data)
        self.assertEqual(resp.status_code, 302)

        instance.refresh_from_db()
        self.assertEqual(instance.name, new_name)
        self.mock_set_host_info.assert_called_once_with(
            mac='22-33-44-55-66-77',
            name='foobar',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time='')

        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["hostname"],
            new_name
        )
        self.mock_refresh_info_cache.assert_called_once()

    def test_update_remote_errored(self):
        new_name = "foobar"
        instance, post_data = self.get_instance_and_post_data(name=new_name)

        def func(**kwargs):
            raise RuntimeError("Foo Bar")

        self.set_set_host_info_side_effect(func)

        with mock.patch("my_router.models.Router.save") as mock_save:
            resp = self.client.post(
                self.device_edit_url(instance.pk), data=post_data)

            mock_save.assert_not_called()

        self.assertEqual(resp.status_code, 302)

        self.assertAddMessageCalledWith("Foo Bar")

        self.mock_set_host_info.assert_called_once_with(
            mac='22-33-44-55-66-77',
            name='foobar',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time='')

        # not changed
        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["hostname"],
            "DEVICE1"
        )
        self.mock_refresh_info_cache.assert_not_called()

    def test_post_change_blocked_ok(self):
        blocked = True
        instance, post_data = self.get_instance_and_post_data(is_blocked=blocked)

        with mock.patch("my_router.models.Router.save") as mock_save:
            resp = self.client.post(
                self.device_edit_url(instance.pk), data=post_data)
            self.assertEqual(resp.status_code, 302)
            mock_save.assert_not_called()

        self.mock_set_host_info.assert_called_once_with(
            mac='22-33-44-55-66-77',
            name='DEVICE1',
            is_blocked=True,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time='')

        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["blocked"],
            "1"
        )
        self.mock_refresh_info_cache.assert_called_once()

    def test_post_change_up_download_limit_ok(self):
        for _field, value in [("down_limit", 10), ("up_limit", 12)]:
            kwargs = {_field: value}
            instance, post_data = self.get_instance_and_post_data(**kwargs)

            with mock.patch("my_router.models.Router.save") as mock_save:
                resp = self.client.post(
                    self.device_edit_url(instance.pk), data=post_data)
                self.assertEqual(resp.status_code, 302)
                mock_save.assert_not_called()

            self.mock_set_host_info.assert_called_once()

            self.assertEqual(
                self.test_cache.get(
                    get_device_cache_key(
                        self.router.id, instance.mac))[_field],
                value
            )
            self.mock_refresh_info_cache.assert_called_once()

            self.mock_set_host_info.reset_mock()
            self.mock_refresh_info_cache.reset_mock()

    def test_post_limit_time_ok(self):
        instance, post_data = self.get_instance_and_post_data(
            limit_time=["limit_time_1", "limit_time_3"])

        with mock.patch("my_router.models.Router.save") as mock_save:
            resp = self.client.post(
                self.device_edit_url(instance.pk), data=post_data)
            self.assertEqual(resp.status_code, 302)
            mock_save.assert_not_called()

        expected_value = "limit_time_1,limit_time_3"

        self.mock_set_host_info.assert_called_once_with(
            mac='22-33-44-55-66-77',
            name='DEVICE1',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time=expected_value)

        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["limit_time"],
            expected_value
        )
        self.mock_refresh_info_cache.assert_called_once()

    def test_post_forbid_domain_ok(self):
        instance, post_data = self.get_instance_and_post_data(
            forbid_domain=["forbid_domain_4", "forbid_domain_5"])

        with mock.patch("my_router.models.Router.save") as mock_save:
            resp = self.client.post(
                self.device_edit_url(instance.pk), data=post_data)
            self.assertEqual(resp.status_code, 302)
            mock_save.assert_not_called()

        expected_value = "forbid_domain_4,forbid_domain_5"

        self.mock_set_host_info.assert_called_once_with(
            mac='22-33-44-55-66-77',
            name='DEVICE1',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain=expected_value,
            limit_time="")

        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["forbid_domain"],
            expected_value
        )

        self.mock_refresh_info_cache.assert_called_once()

    def test_post_another_case(self):
        mac = "44-44-44-44-44-44"
        expected_limit_time = "limit_time_5"
        expected_forbid_domain = "forbid_domain_4"
        instance, post_data = self.get_instance_and_post_data(
            mac=mac,
            forbid_domain=[expected_forbid_domain],
            limit_time=[expected_limit_time],
            up_limit=0,
            down_limit=5
        )

        with mock.patch("my_router.models.Router.save") as mock_save:
            resp = self.client.post(
                self.device_edit_url(instance.pk), data=post_data)
            self.assertEqual(resp.status_code, 302)
            mock_save.assert_not_called()

        self.mock_set_host_info.assert_called_once_with(
            mac=mac,
            name='LIMITED_HOST2',
            is_blocked=False,
            down_limit=5,
            up_limit=0,
            forbid_domain=expected_forbid_domain,
            limit_time=expected_limit_time)

        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["forbid_domain"],
            expected_forbid_domain
        )

        self.assertEqual(
            self.test_cache.get(
                get_device_cache_key(
                    self.router.id, instance.mac))["limit_time"],
            expected_limit_time
        )

        self.mock_refresh_info_cache.assert_called_once()
