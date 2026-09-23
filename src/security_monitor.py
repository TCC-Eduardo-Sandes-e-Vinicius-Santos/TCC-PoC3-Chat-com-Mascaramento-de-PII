from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import FrozenSet, Optional

from kafka import KafkaConsumer
from kafka.errors import KafkaError

DEFAULT_BOOTSTRAP_SERVERS = "localhost:9092"
SECURITY_LOGS_TOPIC = "security-logs"
CONSUMER_GROUP_ID = "security-monitor"

_KAFKA_API_VERSION = (2, 8, 1)

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
) -> KafkaConsumer:
    """
    Cria um KafkaConsumer assinando o tópico `security-logs` desde o início
    (`auto_offset_reset="earliest"`), permitindo auditar também alertas
    publicados antes do monitor ter sido iniciado.

    `group_id` é parametrizável principalmente para os testes de integração
    (cada execução de teste usa um grupo novo, para sempre ler desde o
    início sem interferência de offsets de execuções anteriores).
    """
    return KafkaConsumer(
        SECURITY_LOGS_TOPIC,
        bootstrap_servers=bootstrap_servers,
        group_id=group_id,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda raw_bytes: raw_bytes.decode("utf-8"),
        api_version=_KAFKA_API_VERSION,
    )


def consume_once(consumer: KafkaConsumer, timeout_ms: int = 5000) -> Optional[SecurityAlert]:
    """
    Consome uma única mensagem (com timeout) e retorna o `SecurityAlert`
    correspondente. Retorna `None` se nada chegar dentro do timeout, ou se a
    mensagem recebida for inválida (descartada com um aviso em log).

    Usado principalmente pelos testes de integração; `consume_and_print()`
    usa o iterador contínuo do `KafkaConsumer` para o uso normal do monitor.
    """
    records = consumer.poll(timeout_ms=timeout_ms, max_records=1)
    for topic_partition, messages in records.items():
        for message in messages:
            try:
                return parse_alert(message.value)
            except InvalidSecurityAlertError as exc:
                logger.warning(
                    "Evento descartado em %s (partição %s, offset %s): %s",
                    topic_partition.topic,
                    topic_partition.partition,
                    message.offset,
                    exc,
                )
                return None
    return None


def consume_and_print(
    bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS,
    consumer: Optional[KafkaConsumer] = None,
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

    logger.info(
        "Monitor de segurança iniciado. Assinando o tópico '%s' em %s ...",
        SECURITY_LOGS_TOPIC,
        bootstrap_servers,
    )
    print(f"=== Central de Monitoramento de Segurança — tópico '{SECURITY_LOGS_TOPIC}' ===")

    try:
        for message in consumer:
            try:
                alert = parse_alert(message.value)
            except InvalidSecurityAlertError as exc:
                logger.warning(
                    "Evento descartado (partição %s, offset %s): %s",
                    message.partition,
                    message.offset,
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