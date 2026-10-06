from __future__ import annotations

import requests

import dlp_llm
from dlp_llm import DLP_FAILURE_TAG, MASK_TAG, DlpError, inspect_and_mask


class _FakeResponse:
    """Dublê mínimo de `requests.Response` para os testes."""

    def __init__(self, json_body=None, status_code=200, raise_for_status_exc=None):
        self._json_body = json_body
        self.status_code = status_code
        self._raise_for_status_exc = raise_for_status_exc

    def raise_for_status(self):
        if self._raise_for_status_exc is not None:
            raise self._raise_for_status_exc

    def json(self):
        if self._json_body is None:
            raise ValueError("resposta sem corpo JSON")
        return self._json_body


def test_inspect_and_mask_empty_message_short_circuits_without_http_call(mocker):
    post_mock = mocker.patch("dlp_llm.requests.post")

    result = inspect_and_mask("   ")

    assert result.was_masked is False
    assert result.alert_type == "NENHUM"
    post_mock.assert_not_called()


def test_inspect_and_mask_detects_and_masks_pii(mocker):
    fake_response = _FakeResponse(json_body={"response": f"Meu CPF é {MASK_TAG}."})
    mocker.patch("dlp_llm.requests.post", return_value=fake_response)

    result = inspect_and_mask("Meu CPF é 123.456.789-10.")

    assert result.was_masked is True
    assert result.alert_type == "PII_DETECTED_BLOCKED"
    assert MASK_TAG in result.masked_message


def test_inspect_and_mask_benign_message_is_not_masked(mocker):
    fake_response = _FakeResponse(json_body={"response": "Oi, tudo bem com você?"})
    mocker.patch("dlp_llm.requests.post", return_value=fake_response)

    result = inspect_and_mask("Oi, tudo bem com você?")

    assert result.was_masked is False
    assert result.alert_type == "NENHUM"
    assert result.masked_message == "Oi, tudo bem com você?"


def test_inspect_and_mask_handles_connection_error(mocker):
    mocker.patch(
        "dlp_llm.requests.post",
        side_effect=requests.ConnectionError("Ollama indisponível"),
    )

    result = inspect_and_mask("mensagem qualquer")

    assert result.was_masked is True
    assert result.masked_message == DLP_FAILURE_TAG
    assert result.alert_type == "ERRO_DLP_INDISPONIVEL"


def test_inspect_and_mask_handles_http_error_status(mocker):
    http_error = requests.HTTPError("500 Server Error")
    fake_response = _FakeResponse(raise_for_status_exc=http_error)
    mocker.patch("dlp_llm.requests.post", return_value=fake_response)

    result = inspect_and_mask("mensagem qualquer")

    assert result.was_masked is True
    assert result.alert_type == "ERRO_DLP_INDISPONIVEL"


def test_inspect_and_mask_handles_malformed_json_response(mocker):
    # Resposta sem a chave "response" esperada -> KeyError interno
    fake_response = _FakeResponse(json_body={"unexpected_field": "valor"})
    mocker.patch("dlp_llm.requests.post", return_value=fake_response)

    result = inspect_and_mask("mensagem qualquer")

    assert result.was_masked is True
    assert result.alert_type == "ERRO_DLP_RESPOSTA_INVALIDA"


def test_inspect_and_mask_handles_empty_model_response(mocker):
    fake_response = _FakeResponse(json_body={"response": "   "})
    mocker.patch("dlp_llm.requests.post", return_value=fake_response)

    result = inspect_and_mask("mensagem qualquer")

    assert result.was_masked is True
    assert result.alert_type == "ERRO_DLP_RESPOSTA_VAZIA"


def test_inspect_and_mask_rejects_none_message():
    try:
        inspect_and_mask(None)
        assert False, "esperava DlpError para message=None"
    except DlpError:
        pass


def test_inspect_and_mask_forwards_custom_model_and_url(mocker):
    post_mock = mocker.patch(
        "dlp_llm.requests.post",
        return_value=_FakeResponse(json_body={"response": "ok"}),
    )

    inspect_and_mask(
        "teste",
        ollama_url="http://localhost:11434/api/generate",
        model="phi3",
        timeout=5.0,
    )

    called_args, called_kwargs = post_mock.call_args
    assert called_args[0] == "http://localhost:11434/api/generate"
    assert called_kwargs["json"]["model"] == "phi3"
    assert called_kwargs["timeout"] == 5.0