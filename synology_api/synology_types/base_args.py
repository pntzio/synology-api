class SynologyArgs(object):
    api: str = ""
    version: int = 0
    method: str = ""

    def members(self):
        return {
            attr: 'false' if isinstance(getattr(self, attr), bool) and not getattr(self, attr) else getattr(self, attr)
            for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}


class SynologyResponse(object):
    error_code = 0
    error_message = ""

    def __init__(self, json_data):
        self.json_data = json_data
        self.success: bool = self.json_data['success']
        if not self.success:
            self.error_code = self.json_data['error']['code']


class ApiInfoArgs(SynologyArgs):
    api = "SYNO.API.Info"
    version = 1
    method = "query"
    query = "all"
