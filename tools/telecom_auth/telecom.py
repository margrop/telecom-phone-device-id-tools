import base64
import hashlib
import time
from urllib.parse import urlsplit

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


RSA_PUB_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofd"
    "WzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18"
    "qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMi"
    "PMpq0/XKBO8lYhN/gwIDAQAB"
)

_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json; charset=UTF-8",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "user-agent": "P216010901",
}


class TelecomAuthError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code



class OfficialTransport:
    _ALLOWED_ENDPOINTS = {
        ("appgologinsz.189.cn", 443),
        ("appgologin.189.cn", 9031),
        ("appfuwu.189.cn", 9021),
    }

    def post(self, host, path, body):
        parsed = urlsplit(host)
        try:
            port = parsed.port or 443
        except ValueError as error:
            raise ValueError("Invalid Telecom endpoint") from error
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or (parsed.hostname, port) not in self._ALLOWED_ENDPOINTS
        ):
            raise ValueError("Unofficial Telecom endpoint")
        response = requests.post(
            f"{host.rstrip('/')}{path}",
            json=body,
            headers=_HEADERS,
            timeout=25,
            verify=True,
            allow_redirects=False,
        )
        response.raise_for_status()
        return response.json()


def _caesar(text, shift=2):
    return "".join(chr((ord(char) + shift) & 0xFFFF) for char in text)


def _rsa_encrypt_b64(text):
    public_key = RSA.import_key(base64.b64decode(RSA_PUB_B64))
    cipher = PKCS1_v1_5.new(public_key)
    return base64.b64encode(cipher.encrypt(text.encode("utf-8"))).decode("ascii")


def _aes_ecb_encrypt_b64(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted).decode("ascii")


class TelecomAuth:
    def __init__(self, phone: str, transport=None):
        self.phone = phone
        self._uid = hashlib.md5(f"CT_IOS_11_{phone}".encode()).hexdigest()
        self._key = ""
        self._isct = "0"
        self._slider = None
        self._candidate_device_id = None
        self._transport = transport or OfficialTransport()

    def _update_login_state(self, data):
        if data.get("key"):
            self._key = data["key"]
        if data.get("isChinatelecom") is not None:
            self._isct = str(data["isChinatelecom"])

    def _login_v2(self, code, field_data, header_extra=None):
        headers = {
            "broadAccount": "",
            "broadToken": "",
            "fixedLineAccount": "",
            "fixedLineToken": "",
            "provinceCode": "",
            "code": code,
            "source": "120002",
            "sourcePassword": "TiqmIZ",
            "userLoginName": "",
            "clientType": "#13.4.0#channel50#iPhone 11 Pro Max#",
            "token": "",
            "timestamp": time.strftime("%Y%m%d%H%M%S"),
            "shopId": "20004",
        }
        if header_extra:
            headers.update(header_extra)
        body = {
            "headerInfos": headers,
            "content": {"attach": "iPhone", "fieldData": field_data},
        }
        result = self._transport.post(
            "https://appgologinsz.189.cn", f"/login/client/{code}", body
        )
        if not isinstance(result, dict) or not isinstance(result.get("responseData"), dict):
            raise TelecomAuthError("INVALID_RESPONSE", "Telecom returned an invalid response")
        response_data = result["responseData"]
        data = response_data.get("data") or {}
        if not isinstance(data, dict):
            raise TelecomAuthError("INVALID_RESPONSE", "Telecom returned an invalid response")
        return response_data, data

    def get_challenge(self) -> dict:
        """Fetch key and slider images without sending an SMS."""
        random_fields = {
            "deviceUid": self._uid,
            "imsi": "",
            "key": self._key,
            "payType": "",
            "phoneNum": _caesar(self.phone),
            "salesProdId": "",
            "scene": "55",
            "signSignatureString": "",
            "validationCode": "",
        }
        _, random_data = self._login_v2("getLoginRandomCode", random_fields)
        self._update_login_state(random_data)
        slider_fields = {
            "account": _caesar(self.phone),
            "clientType": "1",
            "deviceUid": _caesar(self._uid),
            "scene": "1",
        }
        _, slider = self._login_v2("getSliderVerificationPicture", slider_fields)
        background = slider.get("backgroundImg") or slider.get("bigImg")
        slider_image = slider.get("sliderImg") or slider.get("smallImg")
        if not background or not slider_image or not slider.get("key") or not slider.get("extra"):
            raise TelecomAuthError("INCOMPLETE_CHALLENGE", "Telecom returned an incomplete slider challenge")
        self._slider = {"key": slider["key"], "extra": slider["extra"]}
        return {
            "background_img": background,
            "slider_img": slider_image,
            "background_width": slider.get("backgroundWidth"),
            "background_height": slider.get("backgroundHeight"),
            "slider_width": slider.get("sliderWidth"),
            "slider_height": slider.get("sliderHeight"),
        }

    def send_sms(self, distance: float, track: str, start_time: int, end_time: int) -> None:
        """Verify the user's drag result and send one SMS."""
        if not self._slider:
            raise TelecomAuthError("MISSING_CHALLENGE", "Fetch a slider challenge first")
        try:
            key = base64.b64decode(self._slider["extra"], validate=True)
        except (ValueError, TypeError) as error:
            raise TelecomAuthError("INVALID_CHALLENGE", "Telecom returned an invalid slider challenge") from error
        verification_fields = {
            "account": _caesar(self.phone),
            "clientType": "1",
            "deviceUid": _caesar(self._uid),
            "distance": _aes_ecb_encrypt_b64("%.4f" % distance, key),
            "endTime": _aes_ecb_encrypt_b64(str(end_time), key),
            "startTime": _aes_ecb_encrypt_b64(str(start_time), key),
            "key": self._slider["key"],
            "scene": "1",
            "shopId": "20002",
            "slidingTrack": _aes_ecb_encrypt_b64(track, key),
        }
        _, verification = self._login_v2("verificationSliderPicture", verification_fields)
        signature = verification.get("signSignatureString")
        if not signature:
            raise TelecomAuthError("SLIDER_REJECTED", "Telecom rejected the slider verification")
        sms_fields = {
            "deviceUid": self._uid,
            "imsi": "",
            "key": self._key,
            "payType": "",
            "phoneNum": _caesar(self.phone),
            "salesProdId": "",
            "scene": "55",
            "signSignatureString": signature,
            "validationCode": "",
        }
        headers, data = self._login_v2("getLoginRandomCode", sms_fields)
        self._update_login_state(data)
        result_code = str(headers.get("resultCode") or "")
        description = str(headers.get("resultDesc") or "")
        if result_code not in ("0", "0000") and not any(
            hint in description for hint in ("成功", "60s", "重复获取")
        ):
            raise TelecomAuthError(result_code or "SMS_FAILED", "Telecom did not send the SMS")

    def submit_sms(self, code: str) -> dict:
        """Submit loginType=2 and return the candidate UID only on token success."""
        timestamp = time.strftime("%Y%m%d%H%M%S")

        def padded(value, length):
            return (value or "")[:length].ljust(length, "$")

        model_prefix = "iPhone 11"[:10].ljust(10, " ")
        plain = (
            model_prefix
            + "16.1."
            + self._uid[:12]
            + self.phone[:11]
            + timestamp[:14]
            + padded(code, 6)
            + padded("0", 4)
            + padded("0.000000", 2)
        )
        fields = {
            "accountType": "",
            "authentication": base64.b64encode(_caesar(code).encode()).decode("ascii"),
            "clientType": "1",
            "deviceUid": self._uid,
            "isChinatelecom": self._isct or "1",
            "loginAuthCipherAsymmertric": _rsa_encrypt_b64(plain),
            "loginType": "2",
            "phoneNum": _caesar(self.phone),
            "signSignatureString": "",
            "systemVersion": "16.1.1",
        }
        headers, data = self._login_v2(
            "userLoginNormal",
            fields,
            {"userLoginName": _caesar(self.phone), "timestamp": timestamp},
        )
        login_result = data.get("loginSuccessResult") or {}
        if not isinstance(login_result, dict) or not login_result.get("token"):
            raise TelecomAuthError("SMS_LOGIN_FAILED", "Telecom SMS login did not succeed")
        self._candidate_device_id = self._uid
        return {"device_id": self._candidate_device_id}

    def verify_device_id(self, password: str) -> bool:
        """Use the candidate as androidId in v1; true only for resultCode 0000."""
        if not self._candidate_device_id:
            raise TelecomAuthError("MISSING_LOGIN", "Complete SMS login before verifying the device")
        timestamp = time.strftime("%Y%m%d%H%M00")
        candidate = self._candidate_device_id
        encrypted_text = (
            f"iPhone 14 15.4.0{candidate[:12]}{self.phone}{timestamp}{password}0$$$0."
        )
        fields = {
            "accountType": "",
            "authentication": _caesar(password),
            "deviceUid": f"3{self.phone}",
            "isChinatelecom": "0",
            "loginAuthCipherAsymmertric": _rsa_encrypt_b64(encrypted_text),
            "loginType": "4",
            "phoneNum": _caesar(self.phone),
            "systemVersion": "15.4.0",
            "androidId": _caesar(candidate),
        }
        body = {
            "content": {"fieldData": fields, "attach": "iPhone"},
            "headerInfos": {
                "code": "userLoginNormal",
                "clientType": "#12.2.0#channel50#iPhone 14 Pro#",
                "timestamp": timestamp,
                "shopId": "20002",
                "source": "110003",
                "sourcePassword": "Sid98s",
                "userLoginName": _caesar(self.phone),
            },
        }
        result = self._transport.post(
            "https://appgologin.189.cn:9031", "/login/client/userLoginNormal", body
        )
        if not isinstance(result, dict) or not isinstance(result.get("responseData"), dict):
            raise TelecomAuthError("INVALID_RESPONSE", "Telecom returned an invalid response")
        return result["responseData"].get("resultCode") == "0000"
