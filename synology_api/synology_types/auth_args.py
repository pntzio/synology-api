from . import base_args


class LoginArgs(base_args.SynologyArgs):
    api = "SYNO.API.Auth"
    method = "login"

    def __init__(self, account: str, passwd: str):
        self.account = account
        self.passwd = passwd
        self.enable_syno_token = "yes"


class LoginResponse(base_args.SynologyResponse):
    def __init__(self, json_data):
        super().__init__(json_data)
        if not self.success:
            return
        self.account: str = self.json_data['data']['account']
        self.device_id: str = self.json_data['data']['device_id']
        self.sid: str = self.json_data['data']['sid']
        self.synotoken: str = self.json_data['data']['synotoken']


class LogoutArgs(base_args.SynologyArgs):
    api = "SYNO.API.Auth"
    method = "logout"
