import base64
import hashlib
import pathlib
import secrets
import sys
import unittest
from unittest import mock

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tools.telecom_auth.telecom import OfficialTransport, TelecomAuth, TelecomAuthError


FIXED_TIME = "20261024120000"


def runtime_digits(length):
    return "".join(secrets.choice("0123456789") for _ in range(length))


def caesar(text):
    return "".join(chr((ord(char) + 2) & 0xFFFF) for char in text)


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.responses = []

    def enqueue(self, data=None, result_code="0000"):
        self.responses.append({
            "responseData": {
                "resultCode": result_code,
                "resultDesc": "",
                "data": data or {},
            }
        })

    def post(self, host, path, body):
        self.calls.append({"host": host, "path": path, "body": body})
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)


class TelecomAuthProtocolTests(unittest.TestCase):
    def setUp(self):
        self.phone = runtime_digits(11)
        self.uid = secrets.token_hex(16)
        self.sms_code = runtime_digits(6)
        self.password = secrets.token_urlsafe(24)
        self.login_token = secrets.token_urlsafe(24)
        self.session_key = secrets.token_urlsafe(24)
        self.next_key = secrets.token_urlsafe(24)
        self.slider_key = secrets.token_urlsafe(24)
        self.slider_signature = secrets.token_urlsafe(24)
        self.slider_aes_key = secrets.token_bytes(16)
        self.background_image = secrets.token_urlsafe(24)
        self.slider_image = secrets.token_urlsafe(24)
        self.distance = 0.1 + secrets.randbelow(9000) / 10000
        self.track = secrets.token_urlsafe(24)
        self.start_time = secrets.randbelow(1_000_000_000_000)
        self.end_time = self.start_time + secrets.randbelow(60_000) + 1
        self.transport = FakeTransport()
        self.client = TelecomAuth(self.phone, transport=self.transport)
        self.client._uid = self.uid
        self.time_patch = mock.patch(
            "tools.telecom_auth.telecom.time.strftime", return_value=FIXED_TIME
        )
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)

    def enqueue_challenge(self):
        self.transport.enqueue({"key": self.session_key, "isChinatelecom": 1})
        self.transport.enqueue({
            "key": self.slider_key,
            "extra": base64.b64encode(self.slider_aes_key).decode("ascii"),
            "backgroundImg": self.background_image,
            "sliderImg": self.slider_image,
            "backgroundWidth": 340,
            "backgroundHeight": 200,
            "sliderWidth": 60,
            "sliderHeight": 200,
        })

    def prepare_to_send(self):
        self.enqueue_challenge()
        self.client.get_challenge()

    def decrypt_slider_field(self, value):
        encrypted = base64.b64decode(value, validate=True)
        decrypted = AES.new(self.slider_aes_key, AES.MODE_ECB).decrypt(encrypted)
        return unpad(decrypted, AES.block_size).decode("utf-8")

    def test_uid_is_deterministic(self):
        client = TelecomAuth(self.phone, transport=self.transport)
        expected = hashlib.md5(f"CT_IOS_11_{self.phone}".encode()).hexdigest()
        self.assertTrue(client._uid == expected)
        self.assertEqual(client._key, "")
        self.assertEqual(client._isct, "0")

    def test_get_challenge_uses_v2_and_returns_slider_dimensions(self):
        self.enqueue_challenge()

        challenge = self.client.get_challenge()

        self.assertEqual(set(challenge), {
            "background_img",
            "slider_img",
            "background_width",
            "background_height",
            "slider_width",
            "slider_height",
        })
        self.assertTrue(challenge["background_img"] == self.background_image)
        self.assertTrue(challenge["slider_img"] == self.slider_image)
        self.assertEqual(challenge["background_width"], 340)
        self.assertEqual(challenge["background_height"], 200)
        self.assertEqual(challenge["slider_width"], 60)
        self.assertEqual(challenge["slider_height"], 200)
        self.assertEqual(
            [call["path"] for call in self.transport.calls],
            [
                "/login/client/getLoginRandomCode",
                "/login/client/getSliderVerificationPicture",
            ],
        )
        first = self.transport.calls[0]
        self.assertEqual(first["host"], "https://appgologinsz.189.cn")
        fields = first["body"]["content"]["fieldData"]
        self.assertTrue(fields["deviceUid"] == self.uid)
        self.assertTrue(fields["phoneNum"] == caesar(self.phone))
        self.assertEqual(fields["signSignatureString"], "")
        headers = first["body"]["headerInfos"]
        self.assertEqual(headers["source"], "120002")
        self.assertEqual(headers["sourcePassword"], "TiqmIZ")
        self.assertEqual(headers["shopId"], "20004")
        self.assertEqual(headers["timestamp"], FIXED_TIME)
        slider_fields = self.transport.calls[1]["body"]["content"]["fieldData"]
        self.assertTrue(slider_fields["account"] == caesar(self.phone))
        self.assertTrue(slider_fields["deviceUid"] == caesar(self.uid))
        self.assertTrue(self.client._key == self.session_key)
        self.assertEqual(self.client._isct, "1")

    def test_send_sms_reuses_challenge_and_decrypts_exact_user_drag(self):
        self.prepare_to_send()
        self.transport.enqueue({"signSignatureString": self.slider_signature})
        self.transport.enqueue({"key": self.next_key, "isChinatelecom": 1})

        result = self.client.send_sms(
            self.distance, self.track, self.start_time, self.end_time
        )

        self.assertIsNone(result)
        self.assertEqual(
            [call["path"] for call in self.transport.calls],
            [
                "/login/client/getLoginRandomCode",
                "/login/client/getSliderVerificationPicture",
                "/login/client/verificationSliderPicture",
                "/login/client/getLoginRandomCode",
            ],
        )
        verification = self.transport.calls[2]["body"]["content"]["fieldData"]
        self.assertTrue(verification["key"] == self.slider_key)
        self.assertEqual(verification["shopId"], "20002")
        expected_plaintext = {
            "distance": "%.4f" % self.distance,
            "slidingTrack": self.track,
            "startTime": str(self.start_time),
            "endTime": str(self.end_time),
        }
        for name, expected in expected_plaintext.items():
            with self.subTest(field=name):
                self.assertTrue(self.decrypt_slider_field(verification[name]) == expected)
        sms_fields = self.transport.calls[3]["body"]["content"]["fieldData"]
        self.assertTrue(sms_fields["key"] == self.session_key)
        self.assertTrue(sms_fields["signSignatureString"] == self.slider_signature)
        self.assertTrue(self.client._key == self.next_key)
        self.assertEqual(len(self.transport.calls), 4)

    def test_slider_rejection_stops_before_sms_request(self):
        self.prepare_to_send()
        self.transport.enqueue({})

        with self.assertRaises(TelecomAuthError):
            self.client.send_sms(self.distance, self.track, self.start_time, self.end_time)

        self.assertEqual(
            [call["path"] for call in self.transport.calls],
            [
                "/login/client/getLoginRandomCode",
                "/login/client/getSliderVerificationPicture",
                "/login/client/verificationSliderPicture",
            ],
        )
        self.assertEqual(len(self.transport.calls), 3)

    def test_sms_failure_raises_after_exactly_one_sms_request(self):
        self.prepare_to_send()
        self.transport.enqueue({"signSignatureString": self.slider_signature})
        self.transport.enqueue({}, result_code="5000")

        with self.assertRaises(TelecomAuthError):
            self.client.send_sms(self.distance, self.track, self.start_time, self.end_time)

        self.assertEqual(
            [call["path"] for call in self.transport.calls[2:]],
            [
                "/login/client/verificationSliderPicture",
                "/login/client/getLoginRandomCode",
            ],
        )
        self.assertEqual(len(self.transport.calls), 4)

    def test_submit_sms_returns_candidate_only_after_token_success(self):
        self.client._key = self.session_key
        self.client._isct = "1"
        self.transport.enqueue({"loginSuccessResult": {"token": self.login_token}})

        result = self.client.submit_sms(self.sms_code)

        self.assertTrue(set(result) == {"device_id"})
        self.assertTrue(result["device_id"] == self.uid)
        call = self.transport.calls[-1]
        self.assertEqual(call["path"], "/login/client/userLoginNormal")
        fields = call["body"]["content"]["fieldData"]
        self.assertEqual(fields["loginType"], "2")
        self.assertTrue(fields["deviceUid"] == self.uid)
        self.assertTrue(fields["phoneNum"] == caesar(self.phone))
        expected_authentication = base64.b64encode(caesar(self.sms_code).encode()).decode()
        self.assertTrue(fields["authentication"] == expected_authentication)
        self.assertTrue(fields["loginAuthCipherAsymmertric"])
        self.assertEqual(
            len(base64.b64decode(fields["loginAuthCipherAsymmertric"])),
            128,
        )
        self.assertTrue(call["body"]["headerInfos"]["userLoginName"] == caesar(self.phone))
        self.assertEqual(call["body"]["headerInfos"]["timestamp"], FIXED_TIME)

    def test_submit_sms_rejects_missing_token(self):
        self.transport.enqueue({"loginSuccessResult": {}})

        with self.assertRaises(TelecomAuthError):
            self.client.submit_sms(self.sms_code)

        self.assertIsNone(self.client._candidate_device_id)

    def test_verify_device_id_uses_candidate_in_v1(self):
        self.transport.enqueue({"loginSuccessResult": {"token": self.login_token}})
        self.client.submit_sms(self.sms_code)
        self.transport.enqueue({}, result_code="0000")

        self.assertTrue(self.client.verify_device_id(self.password))

        call = self.transport.calls[-1]
        self.assertEqual(call["host"], "https://appgologin.189.cn:9031")
        self.assertEqual(call["path"], "/login/client/userLoginNormal")
        fields = call["body"]["content"]["fieldData"]
        self.assertEqual(fields["loginType"], "4")
        self.assertTrue(fields["androidId"] == caesar(self.uid))
        self.assertTrue(fields["authentication"] == caesar(self.password))
        self.assertTrue(fields["loginAuthCipherAsymmertric"])
        self.assertEqual(call["body"]["headerInfos"]["source"], "110003")
        self.assertEqual(call["body"]["headerInfos"]["shopId"], "20002")

    def test_verify_device_id_is_true_only_for_result_code_0000(self):
        self.transport.enqueue({"loginSuccessResult": {"token": self.login_token}})
        self.client.submit_sms(self.sms_code)
        self.transport.enqueue({}, result_code="3006")

        self.assertFalse(self.client.verify_device_id(self.password))

    def test_verify_device_id_requires_successful_sms_login(self):
        with self.assertRaises(TelecomAuthError):
            self.client.verify_device_id(self.password)
        self.assertTrue(len(self.transport.calls) == 0)


class OfficialTransportTests(unittest.TestCase):
    def test_rejects_nonofficial_hosts_and_unsafe_urls(self):
        transport = OfficialTransport()
        unsafe_hosts = (
            "https://example.com",
            "http://appgologinsz.189.cn",
            "https://appgologinsz.189.cn.example.com",
            "https://appgologinsz.189.cn:444",
            "https://user@appgologinsz.189.cn",
        )
        for host in unsafe_hosts:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    transport.post(host, "/login/client/test", {})

    @mock.patch("tools.telecom_auth.telecom.requests.post")
    def test_official_request_keeps_tls_verification_enabled(self, post):
        response = post.return_value
        response.json.return_value = {"responseData": {}}
        transport = OfficialTransport()

        result = transport.post(
            "https://appgologinsz.189.cn", "/login/client/test", {"safe": True}
        )

        self.assertEqual(result, {"responseData": {}})
        self.assertIs(post.call_args.kwargs["verify"], True)
        self.assertIs(post.call_args.kwargs["allow_redirects"], False)
        self.assertEqual(post.call_args.kwargs["timeout"], 25)
        response.raise_for_status.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
