from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final

import requests

DEFAULT_OLLAMA_URL: Final[str] = "http://localhost:11434/api/generate"
DEFAULT_MODEL: Final[str] = "llama3"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0

MASK_TAG: Final[str] = "[DADO_SENSÍVEL_REMOVIDO]"

DLP_FAILURE_TAG: Final[str] = "[ERRO_INSPECAO_DLP]"

_PROMPT_TEMPLATE: Final[str] = """Atue como um filtro de privacidade (DLP).
Sua tarefa é ler a mensagem abaixo e substituir CPFs, e-mails, cartões de
crédito e nomes completos por {mask_tag}.
Responda APENAS com a mensagem higienizada. Não adicione explicações.
Mensagem original: '{message}'
"""

logger = logging.getLogger("dlp_llm")


class DlpError(Exception):
    """Erro genérico deste módulo (uso indevido da API, não falha do Ollama)."""


@dataclass(frozen=True)
class DlpResult:
    """
    Resultado da inspeção de uma mensagem pelo DLP local.
    """
    masked_message: str
    was_masked: bool
    alert_type: str


def _build_prompt(message: str) -> str:
    return _PROMPT_TEMPLATE.format(mask_tag=MASK_TAG, message=message)


def inspect_and_mask(
    message: str,
    *,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> DlpResult:

    if message is None:
        raise DlpError("message não pode ser None.")

    if message.strip() == "":
        return DlpResult(masked_message=message, was_masked=False, alert_type="NENHUM")

    try:
        response = requests.post(
            ollama_url,
            json={
                "model": model,
                "prompt": _build_prompt(message),
                "stream": False,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        masked_message = response.json()["response"].strip()
    except requests.RequestException as exc:
        logger.error("Falha ao conectar no Ollama (%s): %s", ollama_url, exc)
        return DlpResult(
            masked_message=DLP_FAILURE_TAG, was_masked=True, alert_type="ERRO_DLP_INDISPONIVEL"
        )
    except (KeyError, ValueError) as exc:
        logger.error("Resposta inesperada do Ollama: %s", exc)
        return DlpResult(
            masked_message=DLP_FAILURE_TAG, was_masked=True, alert_type="ERRO_DLP_RESPOSTA_INVALIDA"
        )

    if not masked_message:
        logger.warning("Ollama retornou uma resposta vazia; bloqueando por precaução.")
        return DlpResult(
            masked_message=DLP_FAILURE_TAG, was_masked=True, alert_type="ERRO_DLP_RESPOSTA_VAZIA"
        )

    was_masked = MASK_TAG in masked_message
    alert_type = "PII_DETECTED_BLOCKED" if was_masked else "NENHUM"

    return DlpResult(masked_message=masked_message, was_masked=was_masked, alert_type=alert_type)


def main() -> None:
    import sys

    texto = " ".join(sys.argv[1:]) or (
        "Meu email é joao.silva@example.com e meu CPF é 123.456.789-10."
    )
    resultado = inspect_and_mask(texto)
    print(f"Original:  {texto}")
    print(f"Mascarada: {resultado.masked_message}")
    print(f"Violação detectada: {resultado.was_masked} (alert_type={resultado.alert_type})")

if __name__ == "__main__":
    main()    