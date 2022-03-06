from __future__ import annotations

from copy import deepcopy
from unittest import mock

from crispy_forms.layout import Submit
from django.test import TestCase
from django.urls import reverse
from tests.data_for_tests import (ADDED_DEVICE_MAC, BLOCKED_DEVICE1_MAC,
                                  BLOCKED_DEVICE2_MAC, DEVICE0_MAC,
                                  DEVICE1_MAC, LIMIT_DEVICE1_MAC,
                                  LIMIT_DEVICE2_MAC, restructured_info_dicts1,
                                  restructured_info_dicts2)
from tests.mixins import (CacheMixin, MockAddMessageMixing,
                          MockRouterClientMixin, RequestTestMixin)

from my_router.constants import days_const
from my_router.models import Device
from my_router.utils import (DEFAULT_CACHE,
                             get_cached_forbid_domains_cache_key,
                             get_cached_limit_times_cache_key,
                             get_router_device_cache_key)
from my_router.views import (fetch_new_info_save_and_set_cache,
                             get_all_cached_info_with_online_status)


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
        'mac': DEVICE0_MAC,
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
        'mac': DEVICE0_MAC,
        'plan_rule': [],
        'type': '0',
        'up_limit': '0',
        'up_speed': '0'}

    def test_ok(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)
        self.assertDictEqual(
            DEFAULT_CACHE.get(
                get_router_device_cache_key(self.router.id, DEVICE0_MAC)),
            self.device_1_cached_value
        )
        self.assertEqual(Device.objects.count(), 6)

    def test_device_cache_deleted(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)

        self.assertDictEqual(
            DEFAULT_CACHE.get(
                get_router_device_cache_key(self.router.id, DEVICE0_MAC)),
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
            [LIMIT_DEVICE1_MAC]
        )

        # Remove the cache of a device not in dicts1
        DEFAULT_CACHE.delete(
            get_router_device_cache_key(self.router.id, LIMIT_DEVICE2_MAC))

        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_save_and_set_cache(router=self.router)

        self.assertDictEqual(
            DEFAULT_CACHE.get(
                get_router_device_cache_key(self.router.id, DEVICE0_MAC)),
            self.device_1_cached_value_changed
        )
        self.assertEqual(
            DEFAULT_CACHE.get(
                get_cached_limit_times_cache_key(
                    self.router.id))["limit_time_4"]["apply_to"],
            [ADDED_DEVICE_MAC]
        )
        self.assertEqual(
            sorted(DEFAULT_CACHE.get(
                get_cached_forbid_domains_cache_key(
                    self.router.id))["forbid_domain_3"]["apply_to"]),
            [LIMIT_DEVICE1_MAC, ADDED_DEVICE_MAC]
        )

    def test_no_router(self):
        router_id = self.router.id
        self.router.delete()
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router_id=router_id)

    def test_fetch_new_info_save_and_set_cache_ret_invalid(self):
        # An invalid result
        with mock.patch("my_router.views.DEFAULT_CACHE.set") as mock_cache_set:
            self.set_get_restructured_info_dicts_ret({})
            result = fetch_new_info_save_and_set_cache(router=self.router)
            self.assertIsNone(result)

            # assert no cache set call
            mock_cache_set.assert_not_called()


class GetAllCachedInfoWithOnlineStatusTest(
        MockRouterClientMixin, CacheMixin, TestCase):
    # test views.get_all_cached_info_with_online_status
    def test_fetched_new_info(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)

        # No fetch_new_info_save_and_set_cache called,
        # so as to test cache_info is None
        info = get_all_cached_info_with_online_status(self.router)
        host_info_44 = info["host_info"][LIMIT_DEVICE2_MAC]
        with self.assertRaises(KeyError):
            host_info_44["online"]  # noqa
        self.assertEqual(host_info_44["limit_time"], "limit_time_1,limit_time_3")
        self.assertEqual(host_info_44["forbid_domain"], "forbid_domain_1")

        # new info fetched
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_save_and_set_cache(router=self.router)
        info = get_all_cached_info_with_online_status(self.router)

        host_info_44 = info["host_info"][LIMIT_DEVICE2_MAC]
        self.assertFalse(host_info_44["online"])

        # limit_time_1 and forbid_domain_1 is removed
        self.assertEqual(host_info_44["limit_time"], "limit_time_3")
        self.assertEqual(host_info_44["forbid_domain"], "")

    def test_device_cache_deleted(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)

        # new info fetched
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_save_and_set_cache(router=self.router)

        # Remove the cache of a device not in dicts1
        DEFAULT_CACHE.delete(
            get_router_device_cache_key(self.router.id, LIMIT_DEVICE2_MAC))

        info = get_all_cached_info_with_online_status(self.router)
        self.assertNotIn(LIMIT_DEVICE2_MAC, info["host_info"])


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

    def test_info_cached(self):
        # no save for device not changed when fetch_cached_info
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)
        self.client.get(self.fetch_cached_info_url())

        with mock.patch("my_router.models.Device.save") as mock_save:
            fetch_new_info_save_and_set_cache(router=self.router)
            self.client.get(self.fetch_cached_info_url())
            mock_save.assert_not_called()

            self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
            fetch_new_info_save_and_set_cache(router=self.router)
            self.client.get(self.fetch_cached_info_url())
            self.assertEqual(mock_save.call_count, 2)

    def fetch_2_info(self):
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)

        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_save_and_set_cache(router=self.router)

    def test_fetch_cached_device_info(self):
        self.fetch_2_info()
        self.assertEqual(Device.objects.count(), 7)

        resp = self.client.get(self.fetch_cached_info_url())
        self.assertEqual(resp.status_code, 200)
        result = resp.json()
        for device_result in result:
            hostname = device_result["name"]
            online = device_result["online"]
            is_blocked = device_result["is_blocked"]
            forbid_domain = device_result["forbid_domain"]
            limit_time = device_result["limit_time"]
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
        fetch_new_info_save_and_set_cache(router=self.router)
        self.assertEqual(Device.objects.count(), 6)

        resp = self.client.get(self.fetch_cached_info_url())
        self.assertEqual(resp.status_code, 200)

        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_save_and_set_cache(router=self.router)
        self.assertEqual(Device.objects.count(), 7)

        resp = self.client.get(self.fetch_cached_info_url())
        self.assertEqual(resp.status_code, 200)

    def test_fetch_cached_limit_time_info(self):
        self.fetch_2_info()
        resp = self.client.get(self.fetch_cached_info_url(info_name="limit_time"))
        self.assertEqual(resp.status_code, 200)
        for limit_time_result in resp.json():
            index = limit_time_result["index_on_router"]
            apply_to = limit_time_result["apply_to"]

            if index in [22, 25]:
                self.assertEqual(len(apply_to), 1)
            else:
                self.assertEqual(len(apply_to), 0)

    def test_fetch_cached_forbid_domain_info(self):
        self.fetch_2_info()
        resp = self.client.get(self.fetch_cached_info_url(info_name="forbid_domain"))
        self.assertEqual(resp.status_code, 200)
        for forbid_domain_result in resp.json():
            index = forbid_domain_result["index_on_router"]
            apply_to = forbid_domain_result["apply_to"]

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
        fetch_new_info_save_and_set_cache(router=self.router)

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
        fetch_new_info_save_and_set_cache(router=self.router)
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
        fetch_new_info_save_and_set_cache(router=self.router)
        self.assertEqual(Device.objects.count(), 6)

        mac = mac or DEVICE1_MAC
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
            mac=DEVICE1_MAC,
            name='foobar',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time='')

        self.assertEqual(
            self.test_cache.get(
                get_router_device_cache_key(
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

        # not redirected
        self.assertEqual(resp.status_code, 200)

        self.assertAddMessageCalledWith("Foo Bar")

        self.mock_set_host_info.assert_called_once_with(
            mac=DEVICE1_MAC,
            name='foobar',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time='')

        # not changed
        self.assertEqual(
            self.test_cache.get(
                get_router_device_cache_key(
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
            mac=DEVICE1_MAC,
            name='DEVICE1',
            is_blocked=True,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time='')

        self.assertEqual(
            self.test_cache.get(
                get_router_device_cache_key(
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
                    get_router_device_cache_key(
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
            mac=DEVICE1_MAC,
            name='DEVICE1',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain='',
            limit_time=expected_value)

        self.assertEqual(
            self.test_cache.get(
                get_router_device_cache_key(
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
            mac=DEVICE1_MAC,
            name='DEVICE1',
            is_blocked=False,
            down_limit=0,
            up_limit=0,
            forbid_domain=expected_value,
            limit_time="")

        self.assertEqual(
            self.test_cache.get(
                get_router_device_cache_key(
                    self.router.id, instance.mac))["forbid_domain"],
            expected_value
        )

        self.mock_refresh_info_cache.assert_called_once()

    def test_post_another_case(self):
        mac = LIMIT_DEVICE2_MAC
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
                get_router_device_cache_key(
                    self.router.id, instance.mac))["forbid_domain"],
            expected_forbid_domain
        )

        self.assertEqual(
            self.test_cache.get(
                get_router_device_cache_key(
                    self.router.id, instance.mac))["limit_time"],
            expected_limit_time
        )

        self.mock_refresh_info_cache.assert_called_once()


class ListLimitTimeTest(
        RequestTestMixin, MockRouterClientMixin, CacheMixin, TestCase):
    def limit_time_list_url(self):
        return reverse("limit_time-list", args=(self.router.id,))

    def test_get_ok(self):
        resp = self.client.get(self.limit_time_list_url())
        self.assertEqual(resp.status_code, 200)

    def test_login_required(self):
        self.client.logout()
        resp = self.client.get(self.limit_time_list_url())
        self.assertEqual(resp.status_code, 302)


class EditLimitTimeTest(
        RequestTestMixin, MockRouterClientMixin, MockAddMessageMixing, CacheMixin,
        TestCase):
    default_limit_time_name = "test_limit_time"
    default_start_time = "08:00"
    default_end_time = "09:00"
    expected_add_limit_time_name = "limit_time_2"
    default_apply_to = [BLOCKED_DEVICE2_MAC, LIMIT_DEVICE2_MAC]

    def setUp(self):
        super().setUp()
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)

    def limit_time_edit_url(self, limit_time_name: str | int = "limit_time_1"):
        return reverse("limit_time-edit", args=(self.router.id, limit_time_name))

    def limit_time_add_url(self):
        return reverse("limit_time-edit", args=(self.router.id, -1))

    def add_limit_time_post_data(self, disabled_days=None,
                                 disable_apply_to=False, **kwargs):
        days = list(days_const.keys())
        if disabled_days:
            assert isinstance(disabled_days, list)
            days = [d for d in days if d not in disabled_days]

        data = dict(
            name=self.default_limit_time_name,
            days=days,
            start_time=self.default_start_time,
            end_time=self.default_end_time,
        )

        if not disable_apply_to:
            data["apply_to "] = self.default_apply_to

        data.update(**kwargs)
        return data

    @staticmethod
    def get_limit_time_data(limit_time_name, info=restructured_info_dicts1):
        limit_time_data = info["limit_time"][limit_time_name]
        ret = {}
        days = []
        for day in ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']:
            if limit_time_data[day] == '1':
                days.append(day)

        ret["days"] = days
        for field in ['start_time', 'end_time', 'name']:
            ret[field] = limit_time_data[field]

        apply_to = []
        for mac, device in info["host_info"].items():
            if limit_time_data in device["limit_time"].split(","):
                apply_to.append(mac)

        ret['apply_to'] = apply_to
        return ret

    def edit_limit_time_post_data(self, limit_time_name="limit_time_1", **kwargs):
        data = self.get_limit_time_data(limit_time_name=limit_time_name)
        data.update(**kwargs)
        return data

    def test_get_ok(self):
        resp = self.client.get(self.limit_time_edit_url())
        self.assertEqual(resp.status_code, 200)

    def test_get_with_ignored_device_ok(self):
        # ignored device not shown in edit limit_time form
        device_ignored = Device.objects.get(mac=BLOCKED_DEVICE1_MAC)
        device_ignored.ignore = True
        device_ignored.save()
        resp = self.client.get(self.limit_time_edit_url())
        self.assertEqual(resp.status_code, 200)
        form = self.get_response_context_value_by_name(resp, "form")
        mac_choices = [k for k, v in form.fields["apply_to"].choices]
        self.assertNotIn(BLOCKED_DEVICE1_MAC, mac_choices)
        self.assertIn(BLOCKED_DEVICE2_MAC, mac_choices)

    def test_get_login_required(self):
        self.client.logout()
        resp = self.client.get(self.limit_time_edit_url())
        self.assertEqual(resp.status_code, 302)

    def test_get_404(self):
        resp = self.client.get(self.limit_time_edit_url("limit_time_not_exist"))
        self.assertEqual(resp.status_code, 404)

    def test_get_add_ok(self):
        resp = self.client.get(self.limit_time_edit_url(limit_time_name=-1))
        self.assertEqual(resp.status_code, 200)

    def test_add_ok(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_add_url(),
                data=self.add_limit_time_post_data(disabled_days=["mon"]))
            self.assertRedirects(
                resp,
                expected_url=self.limit_time_edit_url(
                    limit_time_name=self.expected_add_limit_time_name),
                status_code=302, fetch_redirect_response=False)
            self.mock_add_limit_time.assert_called_once_with(
                limit_time_name=self.expected_add_limit_time_name,
                desc_name=self.default_limit_time_name,
                start_time=self.default_start_time,
                end_time=self.default_end_time,
                mon=False, tue=True, wed=True,
                thu=True, fri=True, sat=True,
                sun=True
            )
            self.assertEqual(self.mock_set_host_info.call_count, 2)

            # First call in get_available_name, second when done.
            self.assertEqual(mock_fetch_new.call_count, 2)

    def test_add_no_apply_to(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_add_url(),
                data=self.add_limit_time_post_data(disable_apply_to=True))
            self.assertRedirects(
                resp,
                expected_url=self.limit_time_edit_url(
                    limit_time_name=self.expected_add_limit_time_name),
                status_code=302, fetch_redirect_response=False)
            self.mock_add_limit_time.assert_called_once()
            self.assertEqual(self.mock_set_host_info.call_count, 0)

            # First call in get_available_name, second when done.
            self.assertEqual(mock_fetch_new.call_count, 2)

    def test_add_limit_time_errored(self):
        self.mock_add_limit_time.side_effect = lambda x: exec("raise RuntimeError()")

        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_add_url(),
                data=self.add_limit_time_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_limit_time.assert_called_once_with(
                limit_time_name=self.expected_add_limit_time_name,
                desc_name=self.default_limit_time_name,
                start_time=self.default_start_time,
                end_time=self.default_end_time,
                mon=True, tue=True, wed=True,
                thu=True, fri=True, sat=True,
                sun=True
            )

            # First call in get_available_name
            self.assertEqual(mock_fetch_new.call_count, 1)
            self.assertAddMessageCallCount(1)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_add_set_host_info_errored(self):
        self.mock_set_host_info.side_effect = lambda x: exec("raise RuntimeError()")

        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_add_url(),
                data=self.add_limit_time_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_limit_time.assert_called_once_with(
                limit_time_name=self.expected_add_limit_time_name,
                desc_name=self.default_limit_time_name,
                start_time=self.default_start_time,
                end_time=self.default_end_time,
                mon=True, tue=True, wed=True,
                thu=True, fri=True, sat=True,
                sun=True
            )

            # First call in get_available_name
            self.assertEqual(mock_fetch_new.call_count, 1)
            self.assertAddMessageCallCount(1)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 1)

    def test_add_form_invalid(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_add_url(),
                data=self.add_limit_time_post_data(end_time="07:00"))
            self.assertEqual(resp.status_code, 200)

            self.mock_add_limit_time.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 0)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_edit_not_changed_ok(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_edit_url(limit_time_name="limit_time_4"),
                data=self.edit_limit_time_post_data(limit_time_name="limit_time_4"))
            self.assertEqual(resp.status_code, 200)

            self.mock_add_limit_time.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 0)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_edit_apply_to_not_changed_ok(self):
        # this case has apply_to but not changed
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_edit_url(),
                data=self.edit_limit_time_post_data(
                    apply_to=[BLOCKED_DEVICE1_MAC, LIMIT_DEVICE2_MAC]))
            self.assertEqual(resp.status_code, 200)

            self.mock_add_limit_time.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 0)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_edit_apply_to_changed_ok(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.limit_time_edit_url(),
                data=self.edit_limit_time_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_limit_time.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 1)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 2)


class EditForbidDomainTest(
        RequestTestMixin, MockRouterClientMixin, MockAddMessageMixing, CacheMixin,
        TestCase):
    default_domain = "test_forbid_domain.com"
    expected_add_forbid_domain_name = "forbid_domain_1"
    default_apply_to = [BLOCKED_DEVICE2_MAC, LIMIT_DEVICE1_MAC]

    def setUp(self):
        super().setUp()
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts1)
        fetch_new_info_save_and_set_cache(router=self.router)
        self.set_get_restructured_info_dicts_ret(restructured_info_dicts2)
        fetch_new_info_save_and_set_cache(router=self.router)

    def forbid_domain_edit_url(
            self, forbid_domain_name: str | int = "forbid_domain_3"):
        return reverse(
            "forbid_domain-edit", args=(self.router.id, forbid_domain_name))

    def forbid_domain_add_url(self):
        return reverse("forbid_domain-edit", args=(self.router.id, -1))

    def add_forbid_domain_post_data(self, disable_apply_to=False, **kwargs):
        data = dict(domain=self.default_domain)

        if not disable_apply_to:
            data["apply_to "] = self.default_apply_to

        data.update(**kwargs)
        return data

    def edit_forbid_domain_post_data(self, **kwargs):
        # todo: Currently only test change of apply_to
        data = dict(apply_to=[])

        data.update(**kwargs)
        return data

    def test_get_ok(self):
        resp = self.client.get(self.forbid_domain_edit_url())
        self.assertEqual(resp.status_code, 200)

    def test_get_with_ignored_device_ok(self):
        # ignored device not shown in edit forbid_domain form
        device_ignored = Device.objects.get(mac=BLOCKED_DEVICE1_MAC)
        device_ignored.ignore = True
        device_ignored.save()
        resp = self.client.get(self.forbid_domain_edit_url())
        self.assertEqual(resp.status_code, 200)
        form = self.get_response_context_value_by_name(resp, "form")
        mac_choices = [k for k, v in form.fields["apply_to"].choices]
        self.assertNotIn(BLOCKED_DEVICE1_MAC, mac_choices)
        self.assertIn(BLOCKED_DEVICE2_MAC, mac_choices)

    def test_get_login_required(self):
        self.client.logout()
        resp = self.client.get(self.forbid_domain_edit_url())
        self.assertEqual(resp.status_code, 302)

    def test_get_404(self):
        resp = self.client.get(
            self.forbid_domain_edit_url("forbid_domain_not_exist"))
        self.assertEqual(resp.status_code, 404)

    def test_get_add_ok(self):
        resp = self.client.get(self.forbid_domain_edit_url(forbid_domain_name=-1))
        self.assertEqual(resp.status_code, 200)

    def test_add_ok(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_add_url(),
                data=self.add_forbid_domain_post_data(disabled_days=["mon"]))
            self.assertRedirects(
                resp,
                expected_url=self.forbid_domain_edit_url(
                    forbid_domain_name=self.expected_add_forbid_domain_name),
                status_code=302, fetch_redirect_response=False)

            self.mock_add_forbid_domain.assert_called_once_with(
                forbid_domain_name=self.expected_add_forbid_domain_name,
                domain=self.default_domain,
            )
            self.assertEqual(self.mock_set_host_info.call_count, 2)

            # First call in get_available_name, second when done.
            self.assertEqual(mock_fetch_new.call_count, 2)

    def test_add_no_apply_to(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_add_url(),
                data=self.add_forbid_domain_post_data(disable_apply_to=True))
            self.assertRedirects(
                resp,
                expected_url=self.forbid_domain_edit_url(
                    forbid_domain_name=self.expected_add_forbid_domain_name),
                status_code=302, fetch_redirect_response=False)
            self.mock_add_forbid_domain.assert_called_once()
            self.assertEqual(self.mock_set_host_info.call_count, 0)

            # First call in get_available_name, second when done.
            self.assertEqual(mock_fetch_new.call_count, 2)

    def test_add_forbid_domain_errored(self):
        self.mock_add_forbid_domain.side_effect = (
            lambda x: exec("raise RuntimeError()"))

        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_add_url(),
                data=self.add_forbid_domain_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_forbid_domain.assert_called_once_with(
                forbid_domain_name=self.expected_add_forbid_domain_name,
                domain=self.default_domain,
            )

            # First call in get_available_name
            self.assertEqual(mock_fetch_new.call_count, 1)
            self.assertAddMessageCallCount(1)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_add_set_host_info_errored(self):
        self.mock_set_host_info.side_effect = lambda x: exec("raise RuntimeError()")

        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_add_url(),
                data=self.add_forbid_domain_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_forbid_domain.assert_called_once_with(
                forbid_domain_name=self.expected_add_forbid_domain_name,
                domain=self.default_domain,
            )

            # First call in get_available_name
            self.assertEqual(mock_fetch_new.call_count, 1)
            self.assertAddMessageCallCount(1)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 1)

    def test_add_form_invalid(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_add_url(),
                # length more than 32
                data=self.add_forbid_domain_post_data(domain="foobar" * 10))
            self.assertEqual(resp.status_code, 200)

            self.mock_add_forbid_domain.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 0)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_edit_not_changed_ok(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_edit_url(
                    forbid_domain_name="forbid_domain_5"),
                data=self.edit_forbid_domain_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_forbid_domain.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 0)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_edit_apply_to_not_changed_ok(self):
        # this case has apply_to but not changed
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_edit_url("forbid_domain_3"),
                data=self.edit_forbid_domain_post_data(
                    apply_to=[LIMIT_DEVICE1_MAC, ADDED_DEVICE_MAC]))
            self.assertEqual(resp.status_code, 200)

            self.mock_add_forbid_domain.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 0)
            self.assertAddMessageCallCount(0)

            # set_host_info is not reached
            self.assertEqual(self.mock_set_host_info.call_count, 0)

    def test_edit_apply_to_changed_ok(self):
        with mock.patch(
                "my_router.views.fetch_new_info_save_and_set_cache"
        ) as mock_fetch_new:

            resp = self.client.post(
                self.forbid_domain_edit_url(),
                data=self.edit_forbid_domain_post_data())
            self.assertEqual(resp.status_code, 200)

            self.mock_add_forbid_domain.assert_not_called()

            # get_available_name not called
            self.assertEqual(mock_fetch_new.call_count, 1)
            self.assertAddMessageCallCount(0)

            # set_host_info called twice
            self.assertEqual(self.mock_set_host_info.call_count, 2)
