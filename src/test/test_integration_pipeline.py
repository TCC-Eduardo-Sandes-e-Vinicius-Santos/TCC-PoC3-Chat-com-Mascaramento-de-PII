from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Optional

import pytest

import crypto_aes
import dlp_llm
import security_monitor
from crypto_aes import MessageIntegrityError
from security_monitor import InvalidSecurityAlertError, SecurityAlert, parse_alert


def _send_message(
    *,
    sender_id: str,
    target_id: str,
    chat_id: str,
    raw_text: str,
    dlp_result: dlp_llm.DlpResult,
) -> tuple[dict, Optional[dict]]:

    audit_payload = None
    if dlp_result.was_masked:
        audit_payload = {
            "alert_type": dlp_result.alert_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "chatid": chat_id,
            "user1id": sender_id,
            "user2id": target_id,
        }

    shared_key = crypto_aes.derive_shared_key(sender_id, target_id)
    envelope = crypto_aes.encrypt(dlp_result.masked_message, shared_key)

    message_payload = {
        "from": sender_id,
        "to": target_id,
        "nonce": envelope.nonce,
        "ciphertext": envelope.ciphertext,
    }
    return message_payload, audit_payload


def _receive_message(*, my_id: str, target_id: str, message_payload: dict) -> str:
    """Reproduz o fluxo de RECEPÇÃO de `kafka_consumer_thread()`."""
    shared_key = crypto_aes.derive_shared_key(my_id, target_id)
    return crypto_aes.decrypt(
        ciphertext_b64=message_payload["ciphertext"],
        nonce_b64=message_payload["nonce"],
        key=shared_key,
    )


def test_benign_message_round_trips_without_audit_event():
    dlp_result = dlp_llm.DlpResult(
        masked_message="Oi, tudo bem?", was_masked=False, alert_type="NENHUM"
    )

    message_payload, audit_payload = _send_message(
        sender_id="U-100",
        target_id="U-200",
        chat_id="C-555",
        raw_text="Oi, tudo bem?",
        dlp_result=dlp_result,
    )

    assert audit_payload is None

    received_text = _receive_message(
        my_id="U-200", target_id="U-100", message_payload=message_payload
    )
    assert received_text == "Oi, tudo bem?"


def test_pii_message_is_masked_before_encryption_and_triggers_audit_event():
    original_text = "Meu CPF é 123.456.789-10."
    dlp_result = dlp_llm.DlpResult(
        masked_message=f"Meu CPF é {dlp_llm.MASK_TAG}.",
        was_masked=True,
        alert_type="PII_DETECTED_BLOCKED",
    )

    message_payload, audit_payload = _send_message(
        sender_id="U-100",
        target_id="U-200",
        chat_id="C-555",
        raw_text=original_text,
        dlp_result=dlp_result,
    )

    # A mensagem recebida do outro lado deve estar sempre mascarada
    received_text = _receive_message(
        my_id="U-200", target_id="U-100", message_payload=message_payload
    )
    assert received_text == f"Meu CPF é {dlp_llm.MASK_TAG}."
    assert "123.456.789-10" not in received_text

    # O ciphertext publicado no Kafka nunca contém CPF em claro
    assert "123.456.789-10" not in json.dumps(message_payload)

    # O evento de auditoria deve ter sido gerado corretamente
    assert audit_payload is not None
    alert = SecurityAlert.from_raw(audit_payload)
    assert alert.chatid == "C-555"
    assert alert.user1id == "U-100"
    assert alert.user2id == "U-200"
    assert "123.456.789-10" not in json.dumps(audit_payload)


def test_tampering_during_transport_is_detected_end_to_end():
    dlp_result = dlp_llm.DlpResult(
        masked_message="mensagem confidencial", was_masked=False, alert_type="NENHUM"
    )
    message_payload, _ = _send_message(
        sender_id="U-100",
        target_id="U-200",
        chat_id="C-555",
        raw_text="mensagem confidencial",
        dlp_result=dlp_result,
    )

    raw_ciphertext = bytearray(base64.b64decode(message_payload["ciphertext"]))
    raw_ciphertext[0] ^= 0xFF
    message_payload["ciphertext"] = base64.b64encode(bytes(raw_ciphertext)).decode("ascii")

    with pytest.raises(MessageIntegrityError):
        _receive_message(my_id="U-200", target_id="U-100", message_payload=message_payload)


class _FakeKafkaMessage:
    """Dublê mínimo de uma mensagem do confluent_kafka."""

    def __init__(self, value: bytes, error=None, partition: int = 0, offset: int = 0):
        self._value = value
        self._error = error
        self._partition = partition
        self._offset = offset

    def value(self):
        return self._value

    def error(self):
        return self._error

    def partition(self):
        return self._partition

    def offset(self):
        return self._offset


class _FakeConsumer:
    """Dublê mínimo de confluent_kafka.Consumer, apenas para `poll()`."""

    def __init__(self, messages):
        self._messages = list(messages)

    def poll(self, timeout):
        if not self._messages:
            return None
        return self._messages.pop(0)


def test_consume_once_discards_event_with_extra_field():
    tampered_event = dict(
        alert_type="PII_DETECTED_BLOCKED",
        timestamp="2026-10-06T12:00:00+00:00",
        chatid="C-555",
        user1id="U-100",
        user2id="U-200",
        conteudo_vazado="123.456.789-10",
    )
    fake_consumer = _FakeConsumer(
        [_FakeKafkaMessage(json.dumps(tampered_event).encode("utf-8"))]
    )

    result = security_monitor.consume_once(fake_consumer, timeout=0.1)

    assert result is None


def test_consume_once_accepts_a_valid_event():
    valid_event = dict(
        alert_type="PII_DETECTED_BLOCKED",
        timestamp="2026-10-06T12:00:00+00:00",
        chatid="C-555",
        user1id="U-100",
        user2id="U-200",
    )
    fake_consumer = _FakeConsumer(
        [_FakeKafkaMessage(json.dumps(valid_event).encode("utf-8"))]
    )

    result = security_monitor.consume_once(fake_consumer, timeout=0.1)

    assert result is not None
    assert result.chatid == "C-555"


def test_consume_once_returns_none_when_no_message_available():
    fake_consumer = _FakeConsumer([])
    result = security_monitor.consume_once(fake_consumer, timeout=0.1)
    assert result is None


class _FakeKafkaError:
    """Dublê de confluent_kafka.KafkaError, expondo apenas `.code()`."""

    def __init__(self, code):
        self._code = code

    def code(self):
        return self._code

    def __str__(self):
        return f"FakeKafkaError(code={self._code})"


def test_consume_once_returns_none_when_topic_does_not_exist_yet():
    from confluent_kafka import KafkaError

    error = _FakeKafkaError(KafkaError.UNKNOWN_TOPIC_OR_PART)
    fake_message = _FakeKafkaMessage(value=b"", error=error)
    fake_consumer = _FakeConsumer([fake_message])

    result = security_monitor.consume_once(fake_consumer, timeout=0.1)

    assert result is None


def test_consume_once_returns_none_on_other_kafka_errors():
    error = _FakeKafkaError(code=-195)
    fake_message = _FakeKafkaMessage(value=b"", error=error)
    fake_consumer = _FakeConsumer([fake_message])

    result = security_monitor.consume_once(fake_consumer, timeout=0.1)

    assert result is None


def test_consume_once_returns_none_when_message_value_is_none():
    fake_message = _FakeKafkaMessage(value=None)
    fake_consumer = _FakeConsumer([fake_message])

    result = security_monitor.consume_once(fake_consumer, timeout=0.1)

    assert result is None


def test_build_consumer_returns_a_configured_consumer_without_live_broker():
    consumer = security_monitor.build_consumer(
        bootstrap_servers="localhost:9092", group_id="test-group"
    )
    try:
        assert consumer is not None
    finally:
        consumer.close()


class _FakeConsumerLoop:
    """Dublê de Consumer que simula Ctrl+C após `raise_after` polls."""

    def __init__(self, raise_after: int = 2):
        self.polls = 0
        self.raise_after = raise_after
        self.subscribed_topics = None
        self.closed = False

    def subscribe(self, topics):
        self.subscribed_topics = topics

    def poll(self, timeout):
        self.polls += 1
        if self.polls >= self.raise_after:
            raise KeyboardInterrupt()
        return None

    def close(self):
        self.closed = True


def test_consume_and_print_stops_on_keyboard_interrupt_and_keeps_external_consumer_open(capsys):
    fake_consumer = _FakeConsumerLoop(raise_after=2)

    security_monitor.consume_and_print(consumer=fake_consumer)

    captured = capsys.readouterr()
    assert fake_consumer.subscribed_topics == [security_monitor.SECURITY_LOGS_TOPIC]
    assert "Encerrando monitor de segurança" in captured.out
    assert fake_consumer.closed is False


def test_consume_and_print_closes_internally_created_consumer(mocker, capsys):
    fake_consumer = _FakeConsumerLoop(raise_after=1)
    mocker.patch("security_monitor.build_consumer", return_value=fake_consumer)

    security_monitor.consume_and_print()

    assert fake_consumer.closed is True


class _FakeConsumerLoopWithOneAlert(_FakeConsumerLoop):
    """Entrega um alerta válido no primeiro poll, depois encerra o laço."""

    def __init__(self, valid_raw_event: dict):
        super().__init__(raise_after=2)
        self._valid_raw_event = valid_raw_event

    def poll(self, timeout):
        self.polls += 1
        if self.polls == 1:
            return _FakeKafkaMessage(
                value=json.dumps(self._valid_raw_event).encode("utf-8")
            )
        raise KeyboardInterrupt()


def test_consume_and_print_prints_a_received_alert(capsys):
    valid_event = dict(
        alert_type="PII_DETECTED_BLOCKED",
        timestamp="2026-10-06T12:00:00+00:00",
        chatid="C-555",
        user1id="U-100",
        user2id="U-200",
    )
    fake_consumer = _FakeConsumerLoopWithOneAlert(valid_event)

    security_monitor.consume_and_print(consumer=fake_consumer)

    captured = capsys.readouterr()
    assert "[ALERTA DE SEGURANÇA]" in captured.out
    assert "C-555" in captured.out


def test_build_arg_parser_defaults():
    parser = security_monitor._build_arg_parser()
    args = parser.parse_args([])
    assert args.bootstrap_servers == security_monitor.DEFAULT_BOOTSTRAP_SERVERS
    assert args.verbose is False


def test_build_arg_parser_accepts_custom_flags():
    parser = security_monitor._build_arg_parser()
    args = parser.parse_args(["--bootstrap-servers", "kafka:9092", "--verbose"])
    assert args.bootstrap_servers == "kafka:9092"
    assert args.verbose is True
