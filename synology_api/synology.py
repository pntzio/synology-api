from .auth import Authentication
from .downloadstation import DownloadStation
from .synology_types import LoginResponse


class Synology:
    def __init__(self, ip_address: str, port: int, secure: bool):
        self.auth = Authentication(ip_address=ip_address, port=port, secure=secure)
        self.download_station_ = DownloadStation(self.auth)

    def login(self, account: str, passwd: str) -> LoginResponse:
        return self.auth.login(account, passwd)

    def download_station(self) -> DownloadStation:
        return self.download_station_

