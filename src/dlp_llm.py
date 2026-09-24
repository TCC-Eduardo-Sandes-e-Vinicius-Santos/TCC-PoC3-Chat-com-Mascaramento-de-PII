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

_PROMPT_TEMPLATE: Final[str] = """Você é um filtro de privacidade (DLP) que higieniza mensagens de chat antes do envio.

MASCARE (substitua pela tag {mask_tag}) apenas:
- CPF, RG ou outro documento de identificação
- Número de cartão de crédito
- E-mail
- Endereço completo (rua + número, ou CEP)
- Nome completo de uma PESSOA real (nome + sobrenome). Primeiro nome sozinho NÃO conta.
- Idade de uma pessoa, apenas quando vier junto de outro dado que já a identifique (ex.: nome completo + idade)

NÃO MASCARE (mantenha exatamente como está):
- Nomes de empresas, marcas, filmes, jogos, times ou produtos (ex.: "Matrix", "Ambev", "Flamengo", "iPhone")
- Primeiro nome isolado, sem sobrenome (ex.: "João", "Maria")
- Números que sejam quantidade, preço, horário, data ou identificador genérico (ex.: "3 unidades", "R$ 350", "15h", "pedido #4521")

Exemplos:
Mensagem: 'Meu CPF é 123.456.789-10, pode confirmar?'
Resposta: 'Meu CPF é {mask_tag}, pode confirmar?'

Mensagem: 'Assisti Matrix ontem com a Maria, foi ótimo'
Resposta: 'Assisti Matrix ontem com a Maria, foi ótimo'

Mensagem: 'O pedido #4521 tem 12 unidades e custou R$ 350'
Resposta: 'O pedido #4521 tem 12 unidades e custou R$ 350'

Mensagem: 'Sou o João Ferreira da Silva, moro na Rua das Flores, 123'
Resposta: 'Sou o {mask_tag}, moro na {mask_tag}'

Regras de formato da resposta:
1. Responda APENAS com a mensagem higienizada — sem aspas, saudações, explicações ou comentários.
2. Se não houver nada para mascarar, responda com a mensagem original, exatamente como veio.
3. Em caso de dúvida real sobre um trecho, PREFIRA NÃO mascarar.

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