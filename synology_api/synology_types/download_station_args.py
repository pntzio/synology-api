from synology_api.synology_types import SynologyArgs, SynologyResponse


class CreateDownloadTaskArgs(SynologyArgs):
    api = "SYNO.DownloadStation2.Task"
    method = "create"

    def __init__(self, url: str, destination: str):
        self.url = url
        self.destination = destination
        self.create_list: bool = False
        self.type: str = "url"


class CreateDownloadTaskResponse(SynologyResponse):
    def __init__(self, json_data):
        super().__init__(json_data)
        if not self.success:
            return
