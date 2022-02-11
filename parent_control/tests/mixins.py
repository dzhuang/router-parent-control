from unittest import mock

from django.test import Client, override_settings
from django.urls import reverse
from tests.factories import UserFactory


class CacheMixin:
    def setUp(self):  # noqa
        super().setUp()
        import django.core.cache as cache
        self.test_cache = cache.caches["default"]
        self.addCleanup(self.test_cache.clear)


class RequestTestMixin(CacheMixin):
    @classmethod
    def setUpTestData(cls):  # noqa
        # Create superuser
        cls.client = Client()
        super().setUpTestData()

    def setUp(self):
        super().setUp()
        self.user = UserFactory()
        self.client.force_login(self.user)

    @property
    def login_url(self):
        return reverse("login")

    def assertFormErrorLoose(self, response, errors, form_name="form"):  # noqa
        """Assert that errors is found in response.context['form'] errors"""
        import itertools
        if errors is None:
            errors = []
        if not isinstance(errors, (list, tuple)):
            errors = [errors]
        try:
            form_errors = ". ".join(list(
                itertools.chain(*response.context[form_name].errors.values())))
        except TypeError:
            form_errors = None

        if form_errors is None or not form_errors:
            if errors:
                self.fail("%s has no error" % form_name)
            else:
                return

        if form_errors:
            if not errors:
                self.fail("%s unexpectedly has following errors: %s"
                          % (form_name, repr(form_errors)))

        for err in errors:
            self.assertIn(err, form_errors)

    def get_response_context_value_by_name(self, response, context_name):
        try:
            value = response.context[context_name]
        except KeyError:
            self.fail("%s does not exist in given response" % context_name)
        else:
            return value

    def assertResponseContextEqual(self, resp, context_name, expected_value):  # noqa
        value = self.get_response_context_value_by_name(resp, context_name)
        try:
            self.assertTrue(float(value) - float(expected_value) <= 1e-04)
            return
        except Exception:
            self.assertEqual(value, expected_value)


class MockAddMessageMixing(object):
    """
    The mixing for testing django.contrib.messages.add_message
    """

    def setUp(self):
        super(MockAddMessageMixing, self).setUp()
        self._fake_add_message_path = "django.contrib.messages.add_message"
        fake_add_message = mock.patch(self._fake_add_message_path)

        self._mock_add_message = fake_add_message.start()
        self.addCleanup(fake_add_message.stop)

    def _get_added_messages(self, join=True):
        try:
            msgs = [
                "'%s'" % str(arg[2])
                for arg, _ in self._mock_add_message.call_args_list]
        except IndexError:
            self.fail("%s is unexpectedly not called." % self._fake_add_message_path)
        else:
            if join:
                return "; ".join(msgs)
            return msgs

    def assertAddMessageCallCount(self, expected_call_count, reset=False):  # noqa
        fail_msg = (
            "%s is unexpectedly called %d times, instead of %d times." %
            (self._fake_add_message_path, self._mock_add_message.call_count,
             expected_call_count))
        if self._mock_add_message.call_count > 0:
            fail_msg += ("The called messages are: %s"
                         % repr(self._get_added_messages(join=False)))
        self.assertEqual(
            self._mock_add_message.call_count, expected_call_count, msg=fail_msg)
        if reset:
            self._mock_add_message.reset_mock()

    def assertAddMessageCalledWith(self, expected_messages, reset=True):  # noqa
        joined_msgs = self._get_added_messages()

        if not isinstance(expected_messages, list):
            expected_messages = [expected_messages]

        not_called = []
        for msg in expected_messages:
            if msg not in joined_msgs:
                not_called.append(msg)

        if not_called:
            fail_msg = "%s unexpectedly not added in messages. " % repr(not_called)
            if joined_msgs:
                fail_msg += "the actual message are \"%s\"" % joined_msgs
            self.fail(fail_msg)
        if reset:
            self._mock_add_message.reset_mock()

    def assertAddMessageNotCalledWith(self, expected_messages, reset=False):  # noqa
        joined_msgs = self._get_added_messages()

        if not isinstance(expected_messages, list):
            expected_messages = [expected_messages]

        called = []
        for msg in expected_messages:
            if msg in joined_msgs:
                called.append(msg)

        if called:
            fail_msg = "%s unexpectedly added in messages. " % repr(called)
            fail_msg += "the actual message are \"%s\"" % joined_msgs
            self.fail(fail_msg)
        if reset:
            self._mock_add_message.reset_mock()

    def reset_add_message_mock(self):
        self._mock_add_message.reset_mock()


class TaskTestMixin(object):
    """
    This test is actually testing without celery dependency.
    """
    def setUp(self):
        super(TaskTestMixin, self).setUp()

        # Emulates the behavior of AsyncResult
        override_settings_kwargs = {"task_always_eager": True}
        celery_fake_overriding = (
            override_settings(**override_settings_kwargs))
        celery_fake_overriding.enable()
        self.addCleanup(celery_fake_overriding.disable)
        update_state_patcher = mock.patch(
            "celery.app.task.Task.update_state", side_effect=mock.MagicMock)
        self.mock_update_state = update_state_patcher.start()
        self.addCleanup(update_state_patcher.stop)