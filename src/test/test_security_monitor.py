from __future__ import annotations

import json

import pytest

from security_monitor import InvalidSecurityAlertError, SecurityAlert, parse_alert

VALID_RAW_ALERT = {
    "alert_type": "PII_DETECTED_BLOCKED",
    "timestamp": "2026-10-06T12:00:00+00:00",
    "chatid": "C-555",
    "user1id": "U-100",
    "user2id": "U-200",
}


def test_from_raw_accepts_a_fully_valid_event():
    alert = SecurityAlert.from_raw(VALID_RAW_ALERT)
    assert alert.alert_type == "PII_DETECTED_BLOCKED"
    assert alert.chatid == "C-555"
    assert alert.user1id == "U-100"
    assert alert.user2id == "U-200"


@pytest.mark.parametrize(
    "missing_field",
    ["alert_type", "timestamp", "chatid", "user1id", "user2id"],
)
def test_from_raw_rejects_event_missing_a_required_field(missing_field):
    raw = dict(VALID_RAW_ALERT)
    del raw[missing_field]

    with pytest.raises(InvalidSecurityAlertError):
        SecurityAlert.from_raw(raw)


def test_from_raw_rejects_event_with_unexpected_extra_field():
    raw = dict(VALID_RAW_ALERT)
    raw["mensagem_original"] = "Meu CPF é 123.456.789-10"

    with pytest.raises(InvalidSecurityAlertError):
        SecurityAlert.from_raw(raw)


def test_from_raw_rejects_non_dict_payload():
    with pytest.raises(InvalidSecurityAlertError):
        SecurityAlert.from_raw(["isto", "não", "é", "um", "dict"])  # type: ignore[arg-type]


@pytest.mark.parametrize("empty_value", ["", None, 123, 12.5, True])
def test_from_raw_rejects_non_string_or_empty_field_values(empty_value):
    raw = dict(VALID_RAW_ALERT)
    raw["alert_type"] = empty_value

    with pytest.raises(InvalidSecurityAlertError):
        SecurityAlert.from_raw(raw)


def test_format_for_display_never_includes_raw_message_content():
    alert = SecurityAlert.from_raw(VALID_RAW_ALERT)
    displayed = alert.format_for_display()

    assert "123.456.789-10" not in displayed
    assert alert.alert_type in displayed
    assert alert.chatid in displayed
    assert alert.user1id in displayed
    assert alert.user2id in displayed


def test_parse_alert_accepts_valid_json_string():
    raw_value = json.dumps(VALID_RAW_ALERT)
    alert = parse_alert(raw_value)
    assert alert == SecurityAlert.from_raw(VALID_RAW_ALERT)


def test_parse_alert_rejects_malformed_json():
    with pytest.raises(InvalidSecurityAlertError):
        parse_alert("{isto nao é json valido")


def test_parse_alert_rejects_json_with_extra_field():
    raw = dict(VALID_RAW_ALERT)
    raw["pii_vazada"] = "cartao de credito 4111 1111 1111 1111"

    with pytest.raises(InvalidSecurityAlertError):
        parse_alert(json.dumps(raw))