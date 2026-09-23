from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import FrozenSet, Optional

# Alteração: Importando da confluent_kafka em vez de kafka-python
from confluent_kafka import Consumer, KafkaError

DEFAULT_BOOTSTRAP_SERVERS = "localhost:9092"
SECURITY_LOGS_TOPIC = "security-logs"
CONSUMER_GROUP_ID = "security-monitor"

_ALLOWED_FIELDS: FrozenSet[str] = frozenset(
    {"alert_type", "timestamp", "chatid", "user1id", "user2id"}
)
_REQUIRED_FIELDS: FrozenSet[str] = _ALLOWED_FIELDS

logger = logging.getLogger("security_monitor")


class SecurityMonitorError(Exception):
    """Erro genérico deste módulo."""


class InvalidSecurityAlertError(SecurityMonitorError):
    """
    Levantado quando um evento recebido no tópico `security-logs` não segue
    o schema: sem um campo obrigatório, com campo extra não previsto, ou por
    não ser um JSON válido.
    """


@dataclass(frozen=True)
class SecurityAlert:
    """Representa um evento de auditoria já validado, vindo de `security-logs`."""

    alert_type: str
    timestamp: str
    chatid: str
    user1id: str
    user2id: str

    @classmethod
    def from_raw(cls, raw: dict) -> "SecurityAlert":
        if not isinstance(raw, dict):
            raise InvalidSecurityAlertError(
                f"Evento de auditoria não é um objeto JSON: {type(raw).__name__}."
            )

        received_fields = set(raw.keys())

        missing = _REQUIRED_FIELDS - received_fields
        if missing:
            raise InvalidSecurityAlertError(
                f"Evento de auditoria incompleto. Campos ausentes: {sorted(missing)}."
            )

        unexpected = received_fields - _ALLOWED_FIELDS
        if unexpected:
            raise InvalidSecurityAlertError(
                f"Evento de auditoria contém campo(s) não esperado(s): "
                f"{sorted(unexpected)}. Rejeitado por precaução (Requisito "
                f"minimização de dados no log de auditoria)."
            )

        values = {field_name: raw[field_name] for field_name in _REQUIRED_FIELDS}
        for field_name, value in values.items():
            if not isinstance(value, str) or not value:
                raise InvalidSecurityAlertError(
                    f"Campo '{field_name}' deve ser uma string não vazia "
                    f"(recebido: {value!r})."
                )

        return cls(**values)

    def format_for_display(self) -> str:
        return (
            f"[ALERTA DE SEGURANÇA] tipo={self.alert_type} "
            f"chat={self.chatid} remetente={self.user1id} "
            f"destinatario={self.user2id} timestamp={self.timestamp}"
        )


def parse_alert(raw_value: str) -> SecurityAlert:
    """
    Faz o parsing e a validação de uma mensagem crua do tópico
    `security-logs`. Levanta `InvalidSecurityAlertError` para JSON malformado
    ou schema inválido.
    """
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise InvalidSecurityAlertError(
            f"Evento de auditoria não é um JSON válido: {exc}"
        ) from exc

    return SecurityAlert.from_raw(payload)


def build_consumer(
    bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS,
    group_id: str = CONSUMER_GROUP_ID,
) -> Consumer:
    """
    Cria um Consumer da confluent_kafka assinando o tópico `security-logs` desde o início.
    """
    return Consumer({
        'bootstrap.servers': bootstrap_servers,
        'group.id': group_id,
        'auto.offset.reset': 'earliest',
        'enable.auto.commit': True
    })


def consume_and_print(
    bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS,
    consumer: Optional[Consumer] = None,
) -> None:
    """
    Loop principal do monitor: consome o tópico `security-logs`
    indefinidamente e imprime cada alerta válido no terminal. Eventos
    malformados são registrados como aviso e ignorados, sem derrubar o
    monitor — uma infração adulterada/malformada não deve conseguir
    silenciar a auditoria.
    """
    owns_consumer = consumer is None
    consumer = consumer or build_consumer(bootstrap_servers)
    consumer.subscribe([SECURITY_LOGS_TOPIC])

    logger.info(
        "Monitor de segurança iniciado. Assinando o tópico '%s' em %s ...",
        SECURITY_LOGS_TOPIC,
        bootstrap_servers,
    )
    print(f"=== Central de Monitoramento de Segurança — tópico '{SECURITY_LOGS_TOPIC}' ===")

    try:
        while True:
            # Substitui o iterador do kafka-python pelo poll() da confluent_kafka
            message = consumer.poll(1.0)
            
            if message is None:
                continue
                
            if message.error():
                # Ignora erro de tópico inexistente antes do primeiro alerta
                if message.error().code() == KafkaError.UNKNOWN_TOPIC_OR_PART:
                    continue
                logger.error("Erro no consumer: %s", message.error())
                continue

            try:
                # O payload vem em bytes, decodificamos para UTF-8 aqui
                raw_value = message.value().decode("utf-8")
                alert = parse_alert(raw_value)
            except InvalidSecurityAlertError as exc:
                logger.warning(
                    "Evento descartado (partição %s, offset %s): %s",
                    message.partition(),
                    message.offset(),
                    exc,
                )
                continue

            print(alert.format_for_display())
    except KeyboardInterrupt:
        print("\nEncerrando monitor de segurança...")
    finally:
        if owns_consumer:
            consumer.close()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Central de monitoramento de segurança da PoC3 — consome "
        "alertas de tentativas de vazamento de PII (tópico 'security-logs')."
    )
    parser.add_argument(
        "--bootstrap-servers",
        default=DEFAULT_BOOTSTRAP_SERVERS,
        help=f"Endereço(s) do broker Kafka (default: {DEFAULT_BOOTSTRAP_SERVERS}).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Habilita logs de DEBUG (inclui eventos descartados por schema inválido).",
    )
    return parser


def main() -> None:
    args = _build_arg_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        consume_and_print(bootstrap_servers=args.bootstrap_servers)
    except KafkaError as exc:
        logger.error("Falha de comunicação com o Kafka: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()