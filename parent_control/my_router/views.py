from copy import deepcopy
from datetime import datetime, time

from crispy_forms.layout import Submit
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.http import (Http404, HttpResponseForbidden, HttpResponseRedirect,
                         JsonResponse)
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import UpdateView
from pyrouter.router_client import RouterClient

from my_router.constants import DAYS_CHOICES, DEFAULT_CACHE, days_const
from my_router.models import Device, Router
from my_router.serializers import (DeviceDataReverseSerializer,
                                   DeviceJsonSerializer, DeviceModelSerializer,
                                   InfoSerializer)
from my_router.utils import (StyledForm, StyledModelForm,
                             get_all_info_cache_key, get_cached_forbid_domains,
                             get_cached_forbid_domains_cache_key,
                             get_cached_limit_times,
                             get_cached_limit_times_cache_key,
                             get_device_db_cache_key,
                             get_router_all_devices_mac_cache_key,
                             get_router_device_cache_key)


def routers_context_processor(request):
    if not request.user.is_authenticated:
        return {}
    return {
        "routers": Router.objects.all()
    }


def fetch_new_info_save_and_set_cache(router_id):
    routers = Router.objects.filter(id=router_id)
    if not routers.count():
        return

    router, = routers
    client: RouterClient = router.get_client()
    new_result = client.get_restructured_info_dicts()

    serializer = InfoSerializer(data=deepcopy(new_result))
    if not serializer.is_valid():
        return

    DEFAULT_CACHE.set(get_all_info_cache_key(router_id), new_result)

    router = Router.objects.get(id=router_id)
    for info in serializer.data["host_info"].values():
        # save/update device form_data into database
        data = deepcopy(info)
        instances = Device.objects.filter(mac=data["mac"])
        if instances.count():
            instance = instances[0]
        else:
            instance = None
        d_serializer = DeviceModelSerializer(instance=instance, data=data)
        d_serializer.is_valid(raise_exception=True)
        if instance is None:
            with transaction.atomic():
                d_serializer.save(router=router)
        else:
            # When fetching remote data, only name and mac is saved in
            # database. So it is expensive to save/update each existing
            # device at each fetch.
            # We cache the name for comparing before determine whether to do
            # the update.
            mac = d_serializer.validated_data["mac"]
            name = d_serializer.validated_data["name"]
            cached_name = DEFAULT_CACHE.get(get_device_db_cache_key(mac))

            if name != cached_name:
                with transaction.atomic():
                    d_serializer.save(router=router)

    limit_time_device_dict = dict()
    forbid_domain_device_dict = dict()

    # {{{ handle host_info
    host_info = new_result["host_info"]

    # update mac set cache
    all_mac_cache_key = get_router_all_devices_mac_cache_key(router_id)
    all_cached_macs: set = (
            DEFAULT_CACHE.get(all_mac_cache_key, set())
            | set(list(host_info.keys())))
    DEFAULT_CACHE.set(all_mac_cache_key, all_cached_macs)

    for mac, info in host_info.items():
        DEFAULT_CACHE.set(get_router_device_cache_key(router_id, mac), info)

    for mac in all_cached_macs:
        # update from ALL device the dict of limit_time and forbid_domain
        # todo: if device removed, delete the cache
        device_info = DEFAULT_CACHE.get(
            get_router_device_cache_key(router_id, mac), None)

        if not device_info:
            # Avoiding device cache deleted
            continue

        limit_time = device_info.get("limit_time", "")
        limit_time_list = limit_time.split(",")
        for lt in limit_time_list:
            limit_time_device_dict[lt]: list = (
                    list(limit_time_device_dict.get(lt, [])) + [mac])

        forbid_domain = device_info.get("forbid_domain", "")
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

    return new_result


def get_all_cached_info_with_online_status(router_id):
    cached_info = DEFAULT_CACHE.get(get_all_info_cache_key(router_id))

    # Avoiding cache cleared
    if not cached_info:
        cached_info = fetch_new_info_save_and_set_cache(router_id)
        assert cached_info

    host_info = cached_info.get("host_info", {})

    limit_time_keys = cached_info.get("limit_time", {}).keys()
    forbid_domain_keys = cached_info.get("forbid_domain", {}).keys()

    all_macs_cached = DEFAULT_CACHE.get(
        get_router_all_devices_mac_cache_key(router_id), [])
    for mac in all_macs_cached:
        if mac not in host_info:
            # devices not present in current cached all_info
            this_device_info = DEFAULT_CACHE.get(
                get_router_device_cache_key(router_id, mac), {})

            if not this_device_info:
                # Avoiding device cache deleted
                continue

            this_device_info["online"] = False

            # limit_time items might have changed
            # todo: this should be done when deleting limit_time and forbid_domain
            limit_time_items = this_device_info.get("limit_time", "").split(",")
            this_device_info["limit_time"] = ",".join(
                [lt for lt in limit_time_items if lt in limit_time_keys])

            # forbid_domain items might have changed
            forbid_domain_items = (
                this_device_info.get("forbid_domain", "").split(","))
            this_device_info["forbid_domain"] = ",".join(
                [fb for fb in forbid_domain_items
                 if fb in forbid_domain_keys])

            host_info[mac] = this_device_info

    cached_info["host_info"] = host_info

    return cached_info


@login_required
def fetch_cached_info(request, router_id, info_name):
    if request.method == "GET":
        all_cached_info = get_all_cached_info_with_online_status(router_id)
        if not all_cached_info:
            return JsonResponse(
                data=[], safe=False)

        serializer = InfoSerializer(data=all_cached_info)
        if serializer.is_valid():
            return JsonResponse(
                data=serializer.get_datatable_data(router_id, info_name),
                safe=False)
        else:
            return JsonResponse(data=serializer.errors, status=400)

    # POST not allowed
    return HttpResponseForbidden()


@login_required
def list_devices(request, router_id):
    return render(request, "my_router/device-list.html", {
        "router_id": router_id,
        "form_description": _("List of devices"),
    })


class DeviceForm(StyledModelForm):
    class Meta:
        model = Device
        fields = ["name", "mac", "ignore", "known",
                  "added_datetime"]

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

        self.fields["mac"].disabled = True
        self.fields["added_datetime"].disabled = True

        self.fields["is_blocked"] = forms.BooleanField(
            label=_("Blocked"),
            initial=is_blocked, required=False)
        self.fields["down_limit"] = forms.IntegerField(
            label=_("Down limit"),
            min_value=0, initial=down_limit)
        self.fields["up_limit"] = forms.IntegerField(
            label=_("Up limit"),
            min_value=0, initial=up_limit)

        self.fields["limit_time"] = forms.MultipleChoiceField(
            label=_("Limit time"),
            choices=limit_time_choices, initial=limit_time_initial,
            required=False)
        self.fields["forbid_domain"] = forms.MultipleChoiceField(
            label=_("Forbid domain"),
            choices=forbid_domain_choices, initial=forbid_domain_initial,
            required=False)

        if not has_error:
            self.helper.add_input(
                Submit("submit", _("Submit")))


class DeviceUpdateView(LoginRequiredMixin, UpdateView):
    object: Device
    model = Device
    form_class = DeviceForm

    def __init__(self, **kwargs):
        super(DeviceUpdateView, self).__init__(**kwargs)
        self.serialized_cached_device_data = None
        self.changed_fields = []
        self.instance_data = None

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()

        try:
            serializer = DeviceJsonSerializer(
                data=DEFAULT_CACHE.get(
                    get_router_device_cache_key(
                        self.kwargs["router_id"], self.object.mac))
            )
            serializer.is_valid(raise_exception=True)
            self.serialized_cached_device_data = serializer.data

            all_info = fetch_new_info_save_and_set_cache(self.object.router.id)
            serializer = InfoSerializer(data=all_info)
            serializer.is_valid(raise_exception=True)
            kwargs.update(serializer.get_device_update_form_kwargs(
                self.kwargs["router_id"], self.object.mac))
        except Exception as e:
            messages.add_message(
                self.request, messages.ERROR, f"{type(e).__name__}: {str(e)}")
            kwargs["has_error"] = True

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

    def update_router_data(self, form_data):
        need_update_remote = False

        cached_data = self.serialized_cached_device_data

        for key in ["name", "is_blocked", "down_limit", "up_limit"]:
            if form_data[key] != cached_data[key]:
                need_update_remote = True
                self.changed_fields.append(key)

        if set(form_data["limit_time"]) != set(cached_data["limit_time"]):
            need_update_remote = True
            self.changed_fields.append("limit_time")

        if set(form_data["forbid_domain"]) != set(cached_data["forbid_domain"]):
            need_update_remote = True
            self.changed_fields.append("forbid_domain")

        if need_update_remote:
            client = self.object.router.get_client()

            client.set_host_info(
                mac=self.object.mac,
                name=form_data["name"],
                is_blocked=form_data["is_blocked"],
                down_limit=form_data["down_limit"],
                up_limit=form_data["up_limit"],
                forbid_domain=",".join(form_data["forbid_domain"]),
                limit_time=",".join(form_data["limit_time"])
            )

        return need_update_remote

    def form_valid(self, form):
        data = form.cleaned_data

        try:
            remote_updated = self.update_router_data(data)
        except Exception as e:
            messages.add_message(
                self.request, messages.ERROR, f"{type(e).__name__}： {str(e)}")
            return self.form_invalid(form)
        else:
            for _field in form.changed_data:
                if _field in ["name", "known", "ignore"]:
                    with transaction.atomic():
                        self.object = form.save()

            if remote_updated:
                self.update_cache_data(data)

        return HttpResponseRedirect(self.get_success_url())

    def update_cache_data(self, form_data):
        self.update_device_cache_data(form_data)
        self.refresh_all_info_cache()

    def update_device_cache_data(self, form_data):
        # update single device cache, because the device can not be access
        # via the router if it is offline

        serializer = DeviceDataReverseSerializer(data=form_data)
        serializer.is_valid(raise_exception=True)

        cache_key = get_router_device_cache_key(self.kwargs["router_id"],
                                                self.object.mac)
        device_cached_data = DEFAULT_CACHE.get(cache_key)
        device_cached_data.update(**serializer.data)

        DEFAULT_CACHE.set(
            get_router_device_cache_key(self.kwargs["router_id"],
                                        self.object.mac),
            device_cached_data
        )

    def refresh_all_info_cache(self):
        # Cached limit_time and forbid_domain can only be updated by
        # fetch_new_info_save_and_set_cache method.
        # We put it as a new method to facilitate tests.

        fetch_new_info_save_and_set_cache(self.kwargs["router_id"])


def do_delete(router_id, name, delete_type):
    # delete info on router, and re fetch and cache the info
    assert delete_type in ["forbid_domain", "limit_time"]
    router = Router.objects.get(id=router_id)
    client = router.get_client()

    if delete_type == "forbid_domain":
        client.delete_forbid_domain(forbid_domain_name=name)
    else:
        client.delete_limit_time(limit_time_name=name)

    # update cached device info (especially those not present when fetch)
    fetch_new_info_save_and_set_cache(router_id)


def get_mac_choice_tuple(router: Router) -> list:
    all_mac_cache_key = get_router_all_devices_mac_cache_key(router.id)
    all_macs = DEFAULT_CACHE.get(all_mac_cache_key)
    apply_to_choices = []
    ignored_device_mac = (
        Device.objects.filter(
            router=router, ignore=True).values_list("mac", flat=True))
    for mac in all_macs:
        if mac in ignored_device_mac:
            continue
        apply_to_choices.append(
            (mac, DEFAULT_CACHE.get(
                get_router_device_cache_key(router.id, mac))["hostname"]))
    return apply_to_choices


def find_available_name(router_id, prefix):
    assert prefix in ["limit_time", "forbid_domain"]
    fetch_new_info_save_and_set_cache(router_id)

    if prefix == "limit_time":
        all_data: dict = get_cached_limit_times(router_id)
    else:
        all_data: dict = get_cached_forbid_domains(router_id)

    all_keys: list = list(all_data.keys())
    numbers = []
    for v in all_keys:
        s = v.split("_")
        numbers.append(int(s[-1]))

    _number = sorted(list(set(list(range(1, max(numbers) + 2)))
                          - set(numbers)))[0]
    return f"{prefix}_{_number}"


class TimePickerInput(forms.TimeInput):
    input_type = 'time'


@login_required
def list_limit_time(request, router_id):
    return render(request, "my_router/limit_time_list.html", {
        "router_id": router_id,
        "form_description": _("List of devices"),
    })


def turn_str_time_to_time_obj(str_time):
    if not str_time.strip():
        return None
    hour, minute = str_time.split(":")
    return time(int(hour), int(minute))


class LimitTimeEditForm(StyledForm):

    def __init__(self, add_new, name, start_time, end_time,
                 days,
                 apply_to_choices, apply_to_initial, *args, **kwargs):
        super().__init__(*args, **kwargs)

        disabled = False
        self.fields["name"] = forms.CharField(
            label=_("Name"),
            max_length=32, required=True,
            disabled=disabled,
            initial=name)

        self.fields["start_time"] = forms.TimeField(
            label=_("Start time"),
            disabled=disabled, initial=start_time,
            widget=TimePickerInput)

        self.fields["end_time"] = forms.TimeField(
            label=_("End time"),
            disabled=disabled, initial=end_time,
            widget=TimePickerInput)

        self.fields["days"] = forms.MultipleChoiceField(
            label=_("Days"), initial=days,
            disabled=disabled, choices=DAYS_CHOICES,
            required=False
        )

        self.fields["apply_to"] = forms.MultipleChoiceField(
            label=_("Apply to"),
            choices=apply_to_choices, initial=apply_to_initial,
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


@login_required
def edit_limit_time(request, router_id, limit_time_name):
    router = get_object_or_404(Router, id=router_id)

    form_description = _("Edit limit time")
    add_new = False
    if limit_time_name == "-1":
        add_new = True
        form_description = _("Add limit time")

    limit_time_infos = get_cached_limit_times(router.id)

    limit_time_name_copy = limit_time_name

    limit_time_info = {}
    apply_to_initial = []
    if not add_new:
        try:
            limit_time_info = limit_time_infos[limit_time_name]
        except KeyError:
            raise Http404()
        apply_to_initial = limit_time_info["apply_to"]

    days = []
    for day in days_const.keys():
        if limit_time_info.get(day) == "1":
            days.append(day)

    start_time = limit_time_info.get("start_time", "")
    if add_new:
        start_time = datetime.now().strftime("%H:%M")

    start_time = turn_str_time_to_time_obj(start_time)

    end_time = turn_str_time_to_time_obj(limit_time_info.get("end_time", ""))

    kwargs = dict(
        add_new=add_new,
        name=limit_time_info.get("name", ""),
        start_time=start_time,
        end_time=end_time,
        days=days,
        apply_to_choices=get_mac_choice_tuple(router),
        apply_to_initial=apply_to_initial)

    if request.method == "POST":
        kwargs.update(data=request.POST)
        form = LimitTimeEditForm(**kwargs)

        # todo: the item itself has changed
        if form.is_valid():
            client = router.get_client()

            is_editing_exist_limit_time = False
            apply_to_changed = False
            new_apply_to = form.cleaned_data["apply_to"]

            if form.has_changed():
                for field in ["name", "start_time", "end_time", "days"]:
                    if field in form.changed_data:
                        if not add_new:
                            is_editing_exist_limit_time = True
                        apply_to_changed = True
                        break
                else:
                    assert "apply_to" in form.changed_data
                    apply_to_changed = True

            if add_new or is_editing_exist_limit_time:
                try:
                    limit_time_name = add_new_limit_time_from_form_data(
                        client, router_id, form)
                except Exception as e:
                    messages.add_message(
                        request, messages.ERROR, f"{type(e).__name__}: {str(e)}")
                    return render(request, "my_router/limit_time-page.html", {
                        "router_id": router_id,
                        "form": form,
                        "form_description": form_description,
                    })

            if apply_to_changed:
                try:
                    apply_limit_time(client, router_id, limit_time_name,
                                     apply_to_initial, new_apply_to)
                except Exception as e:
                    messages.add_message(
                        request, messages.ERROR, f"{type(e).__name__}: {str(e)}")
                    return render(request, "my_router/limit_time-page.html", {
                        "router_id": router_id,
                        "form": form,
                        "form_description": form_description,
                    })

            if form.has_changed():
                if is_editing_exist_limit_time:
                    do_delete(
                        router_id, name=limit_time_name_copy,
                        delete_type="limit_time")
                else:
                    fetch_new_info_save_and_set_cache(router_id)

            if add_new or is_editing_exist_limit_time:
                return HttpResponseRedirect(
                    reverse("limit_time-edit", args=(router_id, limit_time_name)))

    else:
        form = LimitTimeEditForm(**kwargs)

    return render(request, "my_router/limit_time-page.html", {
        "router_id": router_id,
        "form": form,
        "form_description": form_description,
    })


def add_new_limit_time_from_form_data(client, router_id, form):
    limit_time_name = find_available_name(router_id, "limit_time")
    add_limit_time_kwargs = dict(
        limit_time_name=limit_time_name,
        desc_name=form.cleaned_data["name"],
        start_time=form.cleaned_data["start_time"],
        end_time=form.cleaned_data["end_time"]
    )
    for day in days_const:
        add_limit_time_kwargs[day] = day in form.cleaned_data["days"]
    client.add_limit_time(**add_limit_time_kwargs)
    return limit_time_name


def apply_limit_time(client, router_id, limit_time_name, initial_device_names,
                     new_device_names):
    set_info_tuple = []
    added_apply_devices = set(new_device_names) - set(initial_device_names)
    removed_apply_devices = set(initial_device_names) - set(new_device_names)
    for mac in added_apply_devices:
        cached_data = DEFAULT_CACHE.get(
            get_router_device_cache_key(router_id, mac))
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
        cached_data = DEFAULT_CACHE.get(
            get_router_device_cache_key(router_id, mac), {})
        cached_limit_time = cached_data.get("limit_time", "")
        if cached_limit_time == "":
            # when will this happen?
            continue

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
        client.set_host_info(**kwargs)
        DEFAULT_CACHE.set(
            get_router_device_cache_key(router_id, mac), cached_data)


@login_required
def delete_limit_time(request, router_id, limit_time_name):
    if request.method != "POST":
        return HttpResponseForbidden()
    try:
        do_delete(router_id, name=limit_time_name, delete_type="limit_time")
    except Exception as e:
        return JsonResponse(
            data={"error": f"{type(e).__name__}： {str(e)}"}, status=400)

    return JsonResponse(data={"success": True})


@login_required
def list_forbid_domain(request, router_id):
    return render(request, "my_router/forbid_domain-list.html", {
        "router_id": router_id,
        "form_description": _("List of devices"),
    })


class ForbidDomainEditForm(StyledForm):

    def __init__(self, add_new, domain,
                 apply_to_choices, apply_to_initial, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["domain"] = forms.CharField(
            label=_("Domain"),
            help_text=_("Domain name or keyword in domain name"),
            max_length=32, required=True,
            disabled=not add_new,
            initial=domain)

        self.fields["apply_to"] = forms.MultipleChoiceField(
            label=_("Apply to"),
            choices=apply_to_choices, initial=apply_to_initial,
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
    form_description = _("Edit forbid domain")
    if forbid_domain_name == "-1":
        add_new = True
        form_description = _("Add forbid domain")

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
                forbid_domain_name = find_available_name(router_id, "forbid_domain")
                try:
                    client.add_forbid_domain(
                        forbid_domain_name=forbid_domain_name,
                        domain=form.cleaned_data["domain"])
                except Exception as e:
                    messages.add_message(
                        request, messages.ERROR, f"{type(e).__name__}: {str(e)}")
                    return render(request, "my_router/limit_time-page.html", {
                        "router_id": router_id,
                        "form": form,
                        "form_description": form_description,
                    })

            apply_to_changed = False
            new_apply_to = form.cleaned_data["apply_to"]
            if form.has_changed() and "apply_to" in form.changed_data:
                # In edit mode, with only apply_to editable, form_change
                # means apply_to changed
                apply_to_changed = True

            if apply_to_changed:
                set_info_tuple = []
                added_apply_devices = set(new_apply_to) - set(apply_to_initial)
                removed_apply_devices = set(apply_to_initial) - set(new_apply_to)

                for mac in added_apply_devices:
                    cached_data = DEFAULT_CACHE.get(
                        get_router_device_cache_key(router_id, mac))
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
                    cached_data = DEFAULT_CACHE.get(
                        get_router_device_cache_key(router_id, mac))
                    cached_forbid_domain = cached_data.get("forbid_domain", "")
                    if cached_forbid_domain == "":
                        # when will this happen?
                        continue

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
                        DEFAULT_CACHE.set(
                            get_router_device_cache_key(router_id, mac), cached_data)
                    except Exception as e:
                        messages.add_message(
                            request, messages.ERROR, f"{type(e).__name__}: {str(e)}")
                        return render(request, "my_router/forbid_domain-page.html", {
                            "router_id": router_id,
                            "form": form,
                            "form_description": form_description,
                        })

            if form.has_changed():
                fetch_new_info_save_and_set_cache(router_id)

            if add_new:
                return HttpResponseRedirect(
                    reverse(
                        "forbid_domain-edit", args=(router_id, forbid_domain_name)))

    else:
        form = ForbidDomainEditForm(**kwargs)

    return render(request, "my_router/forbid_domain-page.html", {
        "router_id": router_id,
        "form": form,
        "form_description": form_description,
    })


@login_required
def delete_forbid_domain(request, router_id, forbid_domain_name):
    if request.method != "POST":
        return HttpResponseForbidden()
    try:
        do_delete(router_id, name=forbid_domain_name, delete_type="forbid_domain")
    except Exception as e:
        return JsonResponse(
            data={"error": f"{type(e).__name__}： {str(e)}"}, status=400)

    return JsonResponse(data={"success": True})
