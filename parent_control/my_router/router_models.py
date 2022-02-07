class RouterBase:
    def __init__(self):
        pass

    def login(self, password, user_name=None):
        raise NotImplementedError

    def list_devices(self, banned=False):
        raise NotImplementedError


class TLR470GP(RouterBase):
    def login(self, password, user_name=None):
        pass

    def list_devices(self, banned=False):
        pass
