"""Click-through 'how to make this app safer' tips per permission.

Tips are guidance for the device owner / reviewer. They do not change the
PermGuard score.
"""
from __future__ import annotations

from typing import Optional

from .models import Permission, PurposeCompatibility

_GENERIC = (
    "Open Android Settings → Apps → this app → Permissions, and turn this "
    "off if you do not use a feature that needs it."
)

_BY_SUFFIX: dict[str, str] = {
    "CAMERA": "Disable camera access unless you are taking a photo or using the flashlight LED. Use one-time access if Android offers it.",
    "RECORD_AUDIO": "Turn off the microphone unless you are recording or on a call. Watch for background recording.",
    "ACCESS_FINE_LOCATION": "Use approximate location, or 'Allow only while using the app', instead of precise / always-on location.",
    "ACCESS_COARSE_LOCATION": "Revoke location if maps or local search are not part of how you use the app.",
    "ACCESS_BACKGROUND_LOCATION": "Never leave background location on for a simple utility. Switch to 'while using the app'.",
    "READ_CONTACTS": "Deny contacts unless you are sharing or calling someone from inside the app.",
    "WRITE_CONTACTS": "Deny write-contacts; almost no flashlight, calculator or photo tool needs to change your address book.",
    "READ_SMS": "SMS access can intercept one-time codes. Revoke unless this is your SMS or banking app.",
    "SEND_SMS": "Deny send-SMS. Premium-rate and phishing apps abuse this. Use the system SMS app instead.",
    "RECEIVE_SMS": "Deny unless this is your messenger. Receiving SMS is not needed to flash a light or edit a photo.",
    "READ_CALL_LOG": "Call-log access is rarely needed. Revoke it for any utility that is not a dialer.",
    "READ_PHONE_STATE": "Phone-state can reveal your number and call status. Deny unless the app is a phone/VoIP client.",
    "INTERNET": "Internet is install-time on modern Android. If the app works offline, restrict data in Settings → Apps → Mobile data.",
    "READ_EXTERNAL_STORAGE": "Use the system photo/file picker instead of broad storage access.",
    "WRITE_EXTERNAL_STORAGE": "Broad storage write is a data-exfil path. Prefer the MediaStore / SAF picker.",
    "READ_MEDIA_IMAGES": "Allow photos only while using the editor. Revoke afterwards if you do not need gallery access.",
    "READ_MEDIA_VIDEO": "Allow videos only while using a video feature.",
    "READ_MEDIA_AUDIO": "Allow audio files only for a player or recorder.",
    "SYSTEM_ALERT_WINDOW": "Draw-over-apps can overlay fake login screens. Turn this off unless you truly need a bubble/overlay.",
    "BIND_ACCESSIBILITY_SERVICE": "Accessibility can read the screen and tap for you. Only enable for a screen reader you trust.",
    "RECEIVE_BOOT_COMPLETED": "Boot receivers start the app when the phone turns on. Disable autostart if you do not need it.",
    "REQUEST_INSTALL_PACKAGES": "Install-unknown-apps is a malware dropper path. Never grant this to a flashlight or editor.",
    "PACKAGE_USAGE_STATS": "Usage-stats reveals every app you open. Deny unless this is a digital-wellbeing tool.",
}


def tip_for(permission: Permission, compat: Optional[PurposeCompatibility] = None) -> str:
    suffix = permission.name.rsplit(".", 1)[-1]
    tip = _BY_SUFFIX.get(suffix, _GENERIC)
    bits = [tip]
    if compat and compat.verdict == "UNEXPECTED":
        bits.insert(0, "PermGuard: this permission is not needed for the declared app category.")
    if permission.alternatives:
        bits.append("Less-intrusive alternative: " + "; ".join(permission.alternatives[:2]) + ".")
    if permission.excess_conditions:
        bits.append("Typical over-use: " + permission.excess_conditions[0])
    return " ".join(bits)
