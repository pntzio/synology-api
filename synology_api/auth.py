from __future__ import annotations
from typing import Optional
import requests
import json
import pickle

from .synology_types import SynologyArgs, LoginArgs, LoginResponse, CreateDownloadTaskArgs, LogoutArgs
from .error_codes import error_codes, CODE_SUCCESS, download_station_error_codes, file_station_error_codes
from .error_codes import auth_error_codes, virtualization_error_codes
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from .exceptions import SynoConnectionError, HTTPError, JSONDecodeError, LogoutError
from .synology_types.base_args import ApiInfoArgs

USE_EXCEPTIONS: bool = True


class Authentication:
    def __init__(self,
                 ip_address: str,
                 port: int,
                 secure: bool = False,
                 cert_verify: bool = False,
                 dsm_version: int = 7,
                 debug: bool = True,
                 otp_code: Optional[str] = None
                 ) -> None:
        self._ip_address: str = ip_address
        self._port: int = port
        self._sid: Optional[str] = None
        self._syno_token: Optional[str] = None
        self._session_expire: bool = True
        self._verify: bool = cert_verify
        self._version: int = dsm_version
        self._debug: bool = debug
        self._otp_code: Optional[str] = otp_code
        self._account = ""
        if self._verify is False:
            disable_warnings(InsecureRequestWarning)
        schema = 'https' if secure else 'http'
        self._base_url = '%s://%s:%s/webapi/' % (schema, self._ip_address, self._port)
        self._req_session = requests.Session()
        self._load_cookies()

        self.full_api_list = {}
        self.app_api_list = {}

    def _store_cookies(self):
        with open('cookies.pkl', 'wb') as cookie_file:
            pickle.dump(self._req_session.cookies, cookie_file)

    def _load_cookies(self):
        with open('cookies.pkl', 'rb') as cookie_file:
            stored_cookies = pickle.load(cookie_file)
            self._req_session.cookies = stored_cookies

    def verify_cert_enabled(self) -> bool:
        return self._verify

    def login(self, account: str, passwd: str) -> LoginResponse:
        self.update_api()
        response = LoginResponse(self.request_data(LoginArgs(account, passwd)).json())

        if response.success:
            self._syno_token = response.synotoken
            self._session_expire = False
            self._account = account
            self._store_cookies()
        return response

    def logout(self, application: str) -> None:
        logout_api = 'auth.cgi?api=SYNO.API.Auth'
        param = {'version': self._version, 'method': 'logout', 'session': application}

        if USE_EXCEPTIONS:
            try:
                response = requests.get(self._base_url + logout_api, param, verify=self._verify)
                response.raise_for_status()
                response_json = response.json()
                error_code = self._get_error_code(response_json)
            except requests.exceptions.ConnectionError as e:
                raise SynoConnectionError(error_message=e.args[0])
            except requests.exceptions.HTTPError as e:
                raise HTTPError(error_message=str(e.args))
            except requests.exceptions.JSONDecodeError as e:
                raise JSONDecodeError(error_message=str(e.args))
        else:
            response = requests.get(self._base_url + logout_api, param, verify=self._verify)
            error_code = self._get_error_code(response.json())
        self._session_expire = True
        self._sid = None
        if self._debug is True:
            if not error_code:
                print('Successfully logged out.')
            else:
                print('Logout failed: ' + self._get_error_message(error_code, 'Auth'))
        if USE_EXCEPTIONS and error_code:
            raise LogoutError(error_code=error_code)

        return

    def update_api(self) -> None:
        response = self.request_data(ApiInfoArgs())
        json_data = response.json()["data"]

        setattr(LoginArgs, 'version', json_data[LoginArgs.api]["maxVersion"])
        setattr(LogoutArgs, 'version', json_data[LogoutArgs.api]["maxVersion"])
        setattr(CreateDownloadTaskArgs, 'version', json_data[CreateDownloadTaskArgs.api]["maxVersion"])

    def show_api_name_list(self) -> None:
        prev_key = ''
        for key in self.full_api_list:
            if key != prev_key:
                print(key)
                prev_key = key
        return

    def show_json_response_type(self) -> None:
        for key in self.full_api_list:
            for sub_key in self.full_api_list[key]:
                if sub_key == 'requestFormat':
                    if self.full_api_list[key]['requestFormat'] == 'JSON':
                        print(key + '   Returns JSON data')
        return

    def search_by_app(self, app: str) -> None:
        print_check = 0
        for key in self.full_api_list:
            if app.lower() in key.lower():
                print(key)
                print_check += 1
                continue
        if print_check == 0:
            print('Not Found')
        return

    def request_multi_datas(self,
                            compound: dict[object] = None,
                            method: Optional[str] = None,
                            mode: Optional[str] = "sequential",  # "sequential" or "parallel"
                            response_json: bool = True
                            ) -> dict[str, object] | str | list | requests.Response:  # 'post' or 'get'

        '''
        Compound is a json structure that contains multiples requests, you can execute them sequential or parallel

        Example of compound:
        compound = [
            {
                "api": "SYNO.Core.User",
                "method": "list",
                "version": self.core_list["SYNO.Core.User"]
            }
        ]
        '''
        api_path = self.full_api_list['SYNO.Entry.Request']['path']
        api_version = self.full_api_list['SYNO.Entry.Request']['maxVersion']
        url = f"{self._base_url}{api_path}"

        req_param = {
            "api": "SYNO.Entry.Request",
            "method": "request",
            "version": f"{api_version}",
            "mode": mode,
            "stop_when_error": "true",
            "_sid": self._sid,
            "compound": json.dumps(compound)
        }

        if method is None:
            method = 'get'

        ## Request need some headers to work properly
        # X-SYNO-TOKEN is the token that we get when we login
        # We get it from the self._syno_token variable and by param 'enable_syno_token':'yes' in the login request

        if method == 'get':
            response = requests.get(url, req_param, verify=self._verify, headers={"X-SYNO-TOKEN": self._syno_token})
        elif method == 'post':
            response = requests.post(url, req_param, verify=self._verify, headers={"X-SYNO-TOKEN": self._syno_token})

        if response_json is True:
            return response.json()
        else:
            return response

    def request_data(self, args: SynologyArgs) -> requests.Response:
        members = args.members()
        return self._req_session.get(f'{self._base_url}entry.cgi',
                                     params=members,
                                     verify=self._verify,
                                     headers={"X-SYNO-TOKEN": self._syno_token})

    @staticmethod
    def _get_error_code(response: dict[str, object]) -> int:
        if response.get('success'):
            code = CODE_SUCCESS
        else:
            code = response.get('error').get('code')
        return code

    @staticmethod
    def _get_error_message(code: int, api_name: str) -> str:
        if code in error_codes.keys():
            message = error_codes[code]
        elif api_name == 'Auth':
            message = auth_error_codes.get(code, "<Undefined.Auth.Error>")
        elif api_name.find('DownloadStation') > -1:
            message = download_station_error_codes.get(code, "<Undefined.DownloadStation.Error>")
        elif api_name.find('Virtualization') > -1:
            message = virtualization_error_codes.get(code, "<Undefined.Virtualization.Error>")
        elif api_name.find('FileStation') > -1:
            message = file_station_error_codes.get(code, "<Undefined.FileStation.Error>")
        else:
            message = "<Undefined.%s.Error>" % api_name
        return 'Error {} - {}'.format(code, message)

    @property
    def sid(self) -> Optional[str]:
        return self._sid

    @property
    def base_url(self) -> str:
        return self._base_url
