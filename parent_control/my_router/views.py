from copy import deepcopy

from crispy_forms.layout import Submit
from django import forms
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages import ERROR, add_message
from django.db import IntegrityError, transaction
from django.http import Http404, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import UpdateView
from pyrouter.router_client import RouterClient

from my_router.constants import DEFAULT_CACHE
from my_router.models import Device, Router
from my_router.serializers import (DeviceModelSerializer, DeviceSerializer,
                                   InfoSerializer)
from my_router.utils import (StyledForm, StyledModelForm,
                             get_all_info_cache_key, get_cached_forbid_domains,
                             get_cached_forbid_domains_cache_key,
                             get_cached_limit_times,
                             get_cached_limit_times_cache_key,
                             get_device_cache_key,
                             get_router_devices_mac_cache_key)

filtered_select_multiple_css = {'all': ('/static/admin/css/widgets.css',), }
filtered_select_multiple_js = ('/admin/jsi18n',)


def routers_context_processor(request):
    if not request.user.is_authenticated:
        return {}
    return {
        "routers": Router.objects.all()
    }


@login_required
def list_devices(request, router_id):
    return render(request, "my_router/device-list.html", {
        "router_id": router_id,
        "form_description": _("List of devices"),
    })


def get_merged_info_from_cache(router_id):
    all_macs = DEFAULT_CACHE.get(get_router_devices_mac_cache_key(router_id), [])

    last_all_info = DEFAULT_CACHE.get(get_all_info_cache_key(router_id), {})
    host_info = last_all_info.get("host_info", {})

    host_info_updated = False
    for mac in all_macs:
        if mac not in host_info:
            cache_key = get_device_cache_key(mac)
            this_mac_info = DEFAULT_CACHE.get(cache_key, {})
            if this_mac_info:
                # todo: update limit_time and forbid_domain
                this_mac_info["online"] = False
                host_info[mac] = this_mac_info
                host_info_updated = True

    if host_info_updated:
        last_all_info["host_info"] = host_info

    return last_all_info


@login_required
def fetch_cached_info(request, router_id, info_name):
    if request.method == "GET":
        last_all_info = get_merged_info_from_cache(router_id)
        if not last_all_info:
            return JsonResponse(
                data=[], safe=False)

        serializer = InfoSerializer(data=last_all_info)
        if serializer.is_valid():
            router = Router.objects.get(id=router_id)

            if info_name == "device":
                for info in serializer.data["host_info"].values():
                    # save/update device data into database
                    data = deepcopy(info)
                    d_serializer = DeviceModelSerializer(data=data)
                    if d_serializer.is_valid():
                        try:
                            d_serializer.save(router=router)
                        except IntegrityError:
                            data = deepcopy(info)
                            exist_device = Device.objects.get(
                                mac_address=data["mac"])
                            if exist_device.name != Device.name:
                                _serializer = DeviceModelSerializer(
                                    instance=exist_device, data=data)
                                if _serializer.is_valid():
                                    _serializer.save()

            return JsonResponse(
                data=serializer.get_datatable_data(router_id, info_name),
                safe=False)
        else:
            return JsonResponse(data=serializer.errors, status=400)


def find_available_name(router_id, prefix, fetch_latest=False):
    assert prefix in ["limit_time", "forbid_domain"]
    if prefix == "limit_time":
        all_data: dict = get_cached_limit_times(router_id)
    else:
        all_data: dict = get_cached_forbid_domains(router_id)

    if not all_data or fetch_latest:
        fetch_new_info_and_cache(router_id)
        return find_available_name(router_id, prefix)

    all_keys: list = list(all_data.keys())
    numbers = []
    for v in all_keys:
        s = v.split("_")
        numbers.append(int(s[-1]))

    _number = sorted(list(set(list(range(1, max(numbers) + 2)))
                          - set(numbers)))[0]
    return f"{prefix}_{_number}"


def fetch_new_info_and_cache(router_id):
    routers = Router.objects.filter(id=router_id)
    if not routers.count():
        return

    router, = routers
    client: RouterClient = router.get_client()
    new_result = client.get_restructured_info_dicts()

    assert "host_info" in new_result
    assert "limit_time" in new_result
    assert "forbid_domain" in new_result

    limit_time_device_dict = dict()
    forbid_domain_device_dict = dict()

    # {{{ handle host_info
    host_info = new_result["host_info"]

    # update mac list cache
    all_mac_cache_key = get_router_devices_mac_cache_key(router_id)
    all_cached_macs = DEFAULT_CACHE.get(all_mac_cache_key, [])
    online_macs = list(host_info.keys())
    all_cached_macs = set(list(all_cached_macs) + list(online_macs))
    DEFAULT_CACHE.set(all_mac_cache_key, all_cached_macs)

    for mac, info in host_info.items():
        cache_key = get_device_cache_key(mac)
        DEFAULT_CACHE.set(cache_key, info)

    for mac in all_cached_macs:
        device_info = DEFAULT_CACHE.get(get_device_cache_key(mac), None)
        if device_info:
            if "limit_time" in device_info and device_info["limit_time"] != "":
                limit_time = device_info["limit_time"]
                limit_time_list = limit_time.split(",")
                for lt in limit_time_list:
                    limit_time_device_dict[lt]: list = (
                            list(limit_time_device_dict.get(lt, [])) + [mac])

            if ("forbid_domain" in device_info
                    and device_info["forbid_domain"] != ""):
                forbid_domain = device_info["forbid_domain"]
                forbid_domain_list = forbid_domain.split(",")
                for fb in forbid_domain_list:
                    forbid_domain_device_dict[fb]: list = (
                            list(forbid_domain_device_dict.get(fb, [])) + [mac])
    # }}}

    # {{{ handle limit_time

    limit_time_result = new_result["limit_time"]
    for k in limit_time_result.keys():
        limit_time_result[k]["apply_to"] = limit_time_device_dict.get(k, [])

    DEFAULT_CACHE.set(
        get_cached_limit_times_cache_key(router_id),
        limit_time_result)

    # }}}

    # {{{ handle forbid_domain
    forbid_domain_result = new_result["forbid_domain"]

    for k in forbid_domain_result.keys():
        forbid_domain_result[k]["apply_to"] = (
            forbid_domain_device_dict.get(k, []))

    DEFAULT_CACHE.set(
        get_cached_forbid_domains_cache_key(router_id),
        forbid_domain_result)

    # }}}

    DEFAULT_CACHE.set(get_all_info_cache_key(router_id), new_result)

    return new_result


class DeviceForm(StyledModelForm):
    class Meta:
        model = Device
        fields = ["name", "mac_address", 'ignore', "known", "added_datetime"]

    class Media:
        css = filtered_select_multiple_css
        js = filtered_select_multiple_js

    mac_address = forms.CharField(disabled=True)
    added_datetime = forms.DateTimeField(disabled=True)

    def __init__(self, *args, **kwargs):
        limit_time_choices = kwargs.pop("limit_time_choices", ())
        limit_time_initial = kwargs.pop("limit_time_initial", ())
        forbid_domain_choices = kwargs.pop("forbid_domain_choices", ())
        forbid_domain_initial = kwargs.pop("forbid_domain_initial", ())
        down_limit = kwargs.pop("down_limit", 0)
        up_limit = kwargs.pop("up_limit", 0)
        is_blocked = kwargs.pop("is_blocked", False)
        has_error = kwargs.pop("has_error", False)
        super().__init__(*args, **kwargs)

        self.fields["is_blocked"] = forms.BooleanField(
            initial=is_blocked, required=False)
        self.fields["down_limit"] = forms.IntegerField(
            min_value=0, initial=down_limit)
        self.fields["up_limit"] = forms.IntegerField(
            min_value=0, initial=up_limit)

        self.fields["limit_time"] = forms.MultipleChoiceField(
            choices=limit_time_choices, initial=limit_time_initial,
            widget=FilteredSelectMultiple(_("Limit time"), is_stacked=False),
            required=False)
        self.fields["forbid_domain"] = forms.MultipleChoiceField(
            choices=forbid_domain_choices, initial=forbid_domain_initial,
            widget=FilteredSelectMultiple(_("Forbid domain"), is_stacked=False),
            required=False)

        if not has_error:
            self.helper.add_input(
                Submit("submit", _("Submit")))

    def clean_is_blocked(self):
        return "1" if self.cleaned_data["is_blocked"] else "0"


class DeviceUpdateView(LoginRequiredMixin, UpdateView):
    object: Device
    model = Device
    form_class = DeviceForm

    def __init__(self, **kwargs):
        super(DeviceUpdateView, self).__init__(**kwargs)
        self.cached_device_info = None
        self.cached_limit_time = None
        self.cached_forbid_domain = None
        self.changed_fields = []

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()

        try:
            all_info = fetch_new_info_and_cache(self.object.router.id)
            self.cached_device_info = DEFAULT_CACHE.get(
                get_device_cache_key(self.object.mac_address)
            )
        except Exception as e:
            add_message(self.request, ERROR, str(e))
            kwargs["has_error"] = True
            return kwargs

        all_limit_times = all_info["limit_time"]
        all_forbid_domains = all_info["forbid_domain"]

        kwargs["down_limit"] = int(self.cached_device_info["down_limit"])
        kwargs["up_limit"] = int(self.cached_device_info["up_limit"])

        kwargs["limit_time_choices"] = (
            tuple([v[".name"], v["name"]] for k, v in all_limit_times.items()))

        kwargs["forbid_domain_choices"] = (
            tuple([v[".name"], v["domain"]] for k, v in all_forbid_domains.items()))

        self.cached_limit_time = self.cached_device_info.get(
            "limit_time", "").split(",")
        if self.cached_limit_time == [""]:
            self.cached_limit_time = []

        kwargs["is_blocked"] = self.cached_device_info.get(
            "blocked", "0") == "1"

        kwargs["limit_time_initial"] = list(
            v[".name"] for k, v in all_limit_times.items()
            if k in self.cached_limit_time
        )
        self.cached_forbid_domain = (
            self.cached_device_info.get("forbid_domain", "").split(","))
        if self.cached_forbid_domain == [""]:
            self.cached_forbid_domain = []

        kwargs["forbid_domain_initial"] = list(
            v[".name"] for k, v in all_forbid_domains.items()
            if k in self.cached_forbid_domain
        )
        return kwargs

    def get_queryset(self):
        router_id = self.kwargs["router_id"]
        router = get_object_or_404(Router, id=router_id)
        return super().get_queryset().filter(router=router)

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data["form_description"] = _(
            "Update Device {device_name}").format(device_name=self.object.name)
        return context_data

    def set_device_cache_data(self, form_data):
        new_cache_data = deepcopy(self.cached_device_info)
        for field_name in self.changed_fields:
            if field_name == "name":
                new_cache_data["hostname"] = form_data["name"]
            elif field_name in ["limit_time", "forbid_domain"]:
                new_cache_data[field_name] = ",".join(form_data[field_name])
            elif field_name == "is_blocked":
                new_cache_data["blocked"] = form_data["is_blocked"]
            else:
                new_cache_data[field_name] = form_data[field_name]

        DEFAULT_CACHE.set(
            get_device_cache_key(self.cached_device_info["mac"]),
            new_cache_data
        )

    def form_valid(self, form):
        """If the form is valid, save the associated model."""

        client = self.object.router.get_client()
        data = form.cleaned_data

        cached_info = None
        cache_info_serializer = DeviceSerializer(
            data=deepcopy(self.cached_device_info))
        if cache_info_serializer.is_valid(raise_exception=True):
            cached_info = cache_info_serializer.data

        assert cached_info
        need_update_remote = False
        for key in ["name", "is_blocked", "down_limit", "up_limit"]:
            if data[key] != cached_info[key]:
                need_update_remote = True
                self.changed_fields.append(key)

        if not need_update_remote:
            if set(data["limit_time"]) != set(self.cached_limit_time):
                need_update_remote = True
                self.changed_fields.append("limit_time")

            if set(data["forbid_domain"]) != set(self.cached_forbid_domain):
                need_update_remote = True
                self.changed_fields.append("forbid_domain")

        will_proceed_data_save = True
        if need_update_remote:
            limit_time = ",".join(data["limit_time"])
            forbid_domain = ",".join(data["forbid_domain"])

            try:
                client.set_host_info(
                    self.object.mac_address,
                    name=data["name"],
                    is_blocked=data["is_blocked"],
                    down_limit=data["down_limit"],
                    up_limit=data["up_limit"],
                    forbid_domain=forbid_domain,
                    limit_time=limit_time
                )
            except Exception as e:
                add_message(self.request, ERROR, str(e))
                will_proceed_data_save = False

        if will_proceed_data_save:
            with transaction.atomic():
                self.object = form.save()

            self.set_device_cache_data(data)

        return HttpResponseRedirect(self.get_success_url())


class TimePickerInput(forms.TimeInput):
    input_type = 'time'


@login_required
def list_limit_time(request, router_id):
    return render(request, "my_router/limit_time_list.html", {
        "router_id": router_id,
        "form_description": _("List of devices"),
    })


class LimitTimeEditForm(StyledForm):
    class Media:
        css = filtered_select_multiple_css
        js = filtered_select_multiple_js

    def __init__(self, add_new, name, start_time, end_time,
                 mon, tue, wed, thu, fri, sat, sun,
                 apply_to_choices, apply_to_initial, *args, **kwargs):
        super().__init__(*args, **kwargs)

        disabled = not add_new
        self.fields["name"] = forms.CharField(
            max_length=32, required=True,
            disabled=disabled,
            initial=name)
        self.fields["start_time"] = forms.TimeField(
            disabled=disabled, initial=start_time,
            widget=TimePickerInput)
        self.fields["end_time"] = forms.TimeField(
            disabled=disabled, initial=end_time,
            widget=TimePickerInput)

        for day, label, value in [("mon", _("Monday"), mon),
                                  ("tue", _("Tuesday"), tue),
                                  ("wed", _("Wednesday"), wed),
                                  ("thu", _("Thursday"), thu),
                                  ("fri", _("Friday"), fri),
                                  ("sat", _("Saturday"), sat),
                                  ("sun", _("Sunday"), sun)]:
            true_false = True if value == "1" else False
            self.fields[day] = forms.BooleanField(
                label=label, required=False,
                disabled=disabled, initial=true_false)

        self.fields["apply_to"] = forms.MultipleChoiceField(
            choices=apply_to_choices, initial=apply_to_initial,
            widget=FilteredSelectMultiple(_("Limit time"), is_stacked=False),
            required=False
        )

        if add_new:
            self.helper.add_input(
                Submit("submit", _("Add")))
        else:
            self.helper.add_input(
                Submit("submit", _("Update")))

    def clean(self):
        start_time = self.cleaned_data["start_time"]
        end_time = self.cleaned_data["end_time"]
        if end_time < start_time:
            raise forms.ValidationError(
                _('"end_time" should be greater than "start_time"')
            )
        self.cleaned_data["start_time"] = start_time.strftime("%H:%M")
        self.cleaned_data["end_time"] = end_time.strftime("%H:%M")
        return self.cleaned_data


def get_mac_choice_tuple(router: Router) -> list:
    all_mac_cache_key = get_router_devices_mac_cache_key(router.id)
    all_macs = DEFAULT_CACHE.get(all_mac_cache_key)
    apply_to_choices = []
    ignored_device_mac = (
        Device.objects.filter(
            router=router, ignore=True).values_list("mac_address", flat=True))
    for mac in all_macs:
        if mac in ignored_device_mac:
            continue
        apply_to_choices.append(
            (mac, DEFAULT_CACHE.get(get_device_cache_key(mac))["hostname"]))
    return apply_to_choices


@login_required
def edit_limit_time(request, router_id, limit_time_name):
    router = get_object_or_404(Router, id=router_id)

    add_new = False
    if limit_time_name == "-1":
        add_new = True

    limit_time_infos = get_cached_limit_times(router.id)

    limit_time_info = {}
    apply_to_initial = []
    if not add_new:
        limit_time_info = limit_time_infos[limit_time_name]
        apply_to_initial = limit_time_info["apply_to"]

    kwargs = dict(
        add_new=add_new,
        name=limit_time_info.get("name", ""),
        start_time=limit_time_info.get("start_time", ""),
        end_time=limit_time_info.get("end_time", ""),
        mon=limit_time_info.get("mon", "1"),
        tue=limit_time_info.get("tue", "1"),
        wed=limit_time_info.get("wed", "1"),
        thu=limit_time_info.get("thu", "1"),
        fri=limit_time_info.get("fri", "1"),
        sat=limit_time_info.get("sat", "1"),
        sun=limit_time_info.get("sun", "1"),
        apply_to_choices=get_mac_choice_tuple(router),
        apply_to_initial=apply_to_initial)

    if request.method == "POST":
        kwargs.update(data=request.POST)
        form = LimitTimeEditForm(**kwargs)

        # todo: the item itself has changed
        if form.is_valid():
            client = router.get_client()

            if add_new:
                limit_time_name = find_available_name(
                    router_id, "limit_time", fetch_latest=True)

                add_limit_time_kwargs = dict(
                    limit_time_name=limit_time_name,
                    desc_name=form.cleaned_data["name"],
                    start_time=form.cleaned_data["start_time"],
                    end_time=form.cleaned_data["end_time"]
                )

                for day in ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]:
                    add_limit_time_kwargs[day] = form.cleaned_data[day]

                client.add_limit_time(**add_limit_time_kwargs)

            apply_to_changed = False
            new_apply_to = form.cleaned_data["apply_to"]
            if form.has_changed() and "apply_to" in form.changed_data:
                if set(new_apply_to) != set(apply_to_initial):
                    apply_to_changed = True

            if apply_to_changed:
                set_info_tuple = []
                added_apply_devices = set(new_apply_to) - set(apply_to_initial)
                removed_apply_devices = set(apply_to_initial) - set(new_apply_to)

                for mac in added_apply_devices:
                    cached_data = DEFAULT_CACHE.get(get_device_cache_key(mac))
                    cached_limit_time = cached_data.get("limit_time", "")
                    if cached_limit_time == "":
                        cached_limit_time = []
                    else:
                        cached_limit_time = cached_limit_time.split(",")

                    cached_limit_time = list(
                        set(cached_limit_time + [limit_time_name]))
                    cached_data["limit_time"] = ",".join(cached_limit_time)

                    set_info_tuple.append(
                        (dict(
                            mac=mac,
                            name=cached_data["hostname"],
                            is_blocked=cached_data["blocked"],
                            down_limit=cached_data["down_limit"],
                            up_limit=cached_data["up_limit"],
                            forbid_domain=cached_data.get("forbid_domain", ""),
                            limit_time=cached_data["limit_time"]),
                         mac,
                         cached_data)
                    )

                for mac in removed_apply_devices:
                    cached_data = DEFAULT_CACHE.get(get_device_cache_key(mac))
                    cached_limit_time = cached_data.get("limit_time", "")
                    if cached_limit_time == "":
                        cached_limit_time = []
                    else:
                        cached_limit_time = cached_limit_time.split(",")

                    cached_limit_time = list(
                        set(cached_limit_time) - {limit_time_name})
                    cached_data["limit_time"] = ",".join(cached_limit_time)

                    set_info_tuple.append(
                        (dict(
                            mac=mac,
                            name=cached_data["hostname"],
                            is_blocked=cached_data["blocked"],
                            down_limit=cached_data["down_limit"],
                            up_limit=cached_data["up_limit"],
                            forbid_domain=cached_data.get("forbid_domain", ""),
                            limit_time=cached_data["limit_time"]),
                         mac,
                         cached_data)
                    )

                for kwargs, mac, cached_data in set_info_tuple:
                    try:
                        client.set_host_info(**kwargs)
                        DEFAULT_CACHE.set(get_device_cache_key(mac), cached_data)
                    except Exception as e:
                        add_message(request, ERROR, str(e))

        fetch_new_info_and_cache(router_id)

    else:
        form = LimitTimeEditForm(**kwargs)

    form_description = _("Edit limit time")
    if add_new:
        form_description = _("Add limit time")

    return render(request, "my_router/limit_time-page.html", {
        "router_id": router_id,
        "form": form,
        "form_description": form_description,
    })


@login_required
def list_forbid_domain(request, router_id):
    return render(request, "my_router/forbid_domain-list.html", {
        "router_id": router_id,
        "form_description": _("List of devices"),
    })


class ForbidDomainEditForm(StyledForm):
    class Media:
        css = filtered_select_multiple_css
        js = filtered_select_multiple_js

    def __init__(self, add_new, domain,
                 apply_to_choices, apply_to_initial, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["domain"] = forms.CharField(
            max_length=32, required=True,
            disabled=not add_new,
            initial=domain)

        self.fields["apply_to"] = forms.MultipleChoiceField(
            choices=apply_to_choices, initial=apply_to_initial,
            widget=FilteredSelectMultiple(_("Forbid domain"), is_stacked=False),
            required=False
        )

        if add_new:
            self.helper.add_input(
                Submit("submit", _("Add")))
        else:
            self.helper.add_input(
                Submit("submit", _("Update")))


@login_required
def edit_forbid_domain(request, router_id, forbid_domain_name):
    router = get_object_or_404(Router, id=router_id)
    add_new = False
    if forbid_domain_name == "-1":
        add_new = True

    forbid_domain_info = dict()
    apply_to_initial = []
    if not add_new:
        forbid_domain_infos = get_cached_forbid_domains(router.id)
        try:
            forbid_domain_info = forbid_domain_infos[forbid_domain_name]
        except KeyError:
            raise Http404()
        apply_to_initial = forbid_domain_info["apply_to"]

    kwargs = dict(
        add_new=add_new,
        domain=forbid_domain_info.get("domain", ""),
        apply_to_choices=get_mac_choice_tuple(router),
        apply_to_initial=apply_to_initial)

    if request.method == "POST":
        kwargs.update(data=request.POST)
        form = ForbidDomainEditForm(**kwargs)

        # todo: the item itself has changed
        if form.is_valid():
            client = router.get_client()

            if add_new:
                forbid_domain_name = find_available_name(
                    router_id, "forbid_domain", fetch_latest=True)
                client.add_forbid_domain(
                    forbid_domain_name, form.cleaned_data["domain"])

            apply_to_changed = False
            new_apply_to = form.cleaned_data["apply_to"]
            if form.has_changed() and "apply_to" in form.changed_data:
                if set(new_apply_to) != set(apply_to_initial):
                    apply_to_changed = True

            if apply_to_changed:
                set_info_tuple = []
                added_apply_devices = set(new_apply_to) - set(apply_to_initial)
                removed_apply_devices = set(apply_to_initial) - set(new_apply_to)

                for mac in added_apply_devices:
                    cached_data = DEFAULT_CACHE.get(get_device_cache_key(mac))
                    cached_forbid_domain = cached_data.get("forbid_domain", "")
                    if cached_forbid_domain == "":
                        cached_forbid_domain = []
                    else:
                        cached_forbid_domain = cached_forbid_domain.split(",")

                    cached_forbid_domain = list(
                        set(cached_forbid_domain + [forbid_domain_name]))
                    cached_data["forbid_domain"] = ",".join(cached_forbid_domain)

                    set_info_tuple.append(
                        (dict(
                            mac=mac,
                            name=cached_data["hostname"],
                            is_blocked=cached_data["blocked"],
                            down_limit=cached_data["down_limit"],
                            up_limit=cached_data["up_limit"],
                            forbid_domain=cached_data["forbid_domain"],
                            limit_time=cached_data.get("limit_time", "")),
                         mac,
                         cached_data)
                    )

                for mac in removed_apply_devices:
                    cached_data = DEFAULT_CACHE.get(get_device_cache_key(mac))
                    cached_forbid_domain = cached_data.get("forbid_domain", "")
                    if cached_forbid_domain == "":
                        cached_forbid_domain = []
                    else:
                        cached_forbid_domain = cached_forbid_domain.split(",")

                    cached_forbid_domain = list(
                        set(cached_forbid_domain) - {forbid_domain_name})
                    cached_data["forbid_domain"] = ",".join(cached_forbid_domain)

                    set_info_tuple.append(
                        (dict(
                            mac=mac,
                            name=cached_data["hostname"],
                            is_blocked=cached_data["blocked"],
                            down_limit=cached_data["down_limit"],
                            up_limit=cached_data["up_limit"],
                            forbid_domain=cached_data["forbid_domain"],
                            limit_time=cached_data.get("limit_time", "")),
                         mac,
                         cached_data)
                    )

                for kwargs, mac, cached_data in set_info_tuple:
                    try:
                        client.set_host_info(**kwargs)
                        DEFAULT_CACHE.set(get_device_cache_key(mac), cached_data)
                    except Exception as e:
                        add_message(request, ERROR, f"{type(e).__name__}: {str(e)}")

        fetch_new_info_and_cache(router_id)

    else:
        form = ForbidDomainEditForm(**kwargs)

    return render(request, "my_router/forbid_domain-page.html", {
        "router_id": router_id,
        "form": form,
        "form_description": _("Edit limit time"),
    })
