# Attribution

This project includes code adapted from the following open-source projects:

## [yahooor/cn-carrier-monitor](https://github.com/yahooor/cn-carrier-monitor)

- License: MIT
- Copyright (c) 2026 cn-carrier-monitor contributors
- Used for: Telecom v2 SMS login protocol (getLoginRandomCode, getSliderVerificationPicture, verificationSliderPicture, userLoginNormal with loginType=2), slider geometry formula, AES-ECB encryption of slider fields, RSA-PKCS1v15 login cipher, CAESAR encoding.
- Source: `custom_components/cn_carrier_monitor/api/telecom.py`

## [hlhk2017/ChinaTelecomMonitor-Homeassistant-Integration](https://github.com/hlhk2017/ChinaTelecomMonitor-Homeassistant-Integration)

- License: MIT
- Copyright (c) 2025 hlhk2017
- Used for: Telecom v1 service-password login protocol (userLoginNormal with loginType=4), DeviceId (androidId) usage for device trust verification.
- Source: `custom_components/china_telecom/telecom_class.py`
