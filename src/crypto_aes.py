"""
crypto_aes.py — Criptografia simétrica ponta a ponta (AES-256-GCM) da PoC3.

Responsável por:
  - Derivar, de forma determinística, uma chave simétrica de 256 bits
    compartilhada exclusivamente entre um par de IDs de usuário
    (HKDF-SHA256).
  - Cifrar e decifrar mensagens de chat com AES-256 no modo GCM (AEAD),
    garantindo confidencialidade e autenticidade/integridade em uma única
    primitiva, sem exigir um HMAC separado.

Ver docs/arquitetura.md, seção "crypto_aes.py — Criptografia Simétrica
Ponta a Ponta", para o racional de design e as limitações conhecidas
(em especial: a derivação depende apenas dos IDs informados via CLI, sem
um handshake de identidade autenticado).
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE: Final[int] = 12
_KEY_SIZE:   Final[int] = 32
_HKDF_SALT:  Final[bytes] = b"tcc-poc3-chat-mascaramento-pii"
_HKDF_INFO:  Final[bytes] = b"crypto_aes.derive_shared_key"


class CryptoAESError(Exception):
    """Erro genérico deste módulo (entrada inválida, formato malformado etc)."""


class MessageIntegrityError(CryptoAESError):
    """
    Levantado quando a *tag* de autenticação do AES-GCM não confere: a
    mensagem foi adulterada, a chave usada está incorreta, ou o nonce não
    corresponde ao ciphertext fornecido.
    """


@dataclass(frozen=True)
class EncryptedMessage:
    """Envelope de uma mensagem cifrada, pronto para serialização/transporte"""

    # base64
    ciphertext: str
    nonce: str

    def to_dict(self) -> dict:
        return {"ciphertext": self.ciphertext, "nonce": self.nonce}

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedMessage":
        try:
            return cls(ciphertext=data["ciphertext"], nonce=data["nonce"])
        except KeyError as exc:
            raise CryptoAESError(
                f"Campo obrigatório ausente no envelope cifrado: {exc}"
            ) from exc


def derive_shared_key(id_a: str, id_b: str) -> bytes:
    """
    Deriva uma chave simétrica de 256 bits compartilhada exclusivamente pelo
    par (id_a, id_b), via HKDF-SHA256. Os IDs são ordenados antes da derivação, 
    então o par produz sempre a mesma chave, independentemente de quem é
    remetente e quem é destinatário na chamada.
    """
    if not id_a or not id_b:
        raise CryptoAESError(
            "Os dois IDs (id_a, id_b) são obrigatórios e não podem ser vazios."
        )
    if id_a == id_b:
        raise CryptoAESError("id_a e id_b devem ser IDs de usuários distintos.")

    ordered_ids = sorted([str(id_a), str(id_b)])
    ikm = "|".join(ordered_ids).encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    return hkdf.derive(ikm)


def encrypt(plaintext: str, key: bytes) -> EncryptedMessage:
    """
    Cifra `plaintext` (str, UTF-8) com AES-256-GCM usando `key` (32 bytes) e
    um nonce aleatório novo a cada chamada. Retorna um `EncryptedMessage`
    com ciphertext e nonce em base64, prontos para publicação no Kafka.
    """
    _validate_key(key)
    if plaintext is None:
        raise CryptoAESError("plaintext não pode ser None.")

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)

    return EncryptedMessage(
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
    )


def decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    """
    Decifra e valida a autenticidade de uma mensagem cifrada com `encrypt()`.

    Levanta `MessageIntegrityError` se a *tag* de autenticação do GCM não
    conferir (mensagem adulterada, nonce incorreto ou chave errada) e
    `CryptoAESError` para entradas malformadas (ex.: base64 inválido, chave
    com tamanho incorreto).
    """
    _validate_key(key)

    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        nonce = base64.b64decode(nonce_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise CryptoAESError(f"ciphertext/nonce em base64 inválido: {exc}") from exc

    if len(nonce) != _NONCE_SIZE:
        raise CryptoAESError(
            f"Nonce com tamanho inesperado: {len(nonce)} bytes (esperado {_NONCE_SIZE})."
        )

    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise MessageIntegrityError(
            "Falha na verificação de integridade/autenticidade (tag GCM "
            "inválida): a mensagem pode ter sido adulterada, ou a chave/"
            "nonce usados estão incorretos."
        ) from exc

    return plaintext_bytes.decode("utf-8")


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_SIZE:
        got = len(key) if isinstance(key, (bytes, bytearray)) else type(key).__name__
        raise CryptoAESError(
            f"Chave inválida: esperado {_KEY_SIZE} bytes (AES-256), recebido {got}."
        )


def main() -> None:
    demo_key = derive_shared_key("U-100", "U-200")
    demo_message = "[DUMMY] mensagem de teste, com acentuação e emoji 🔒."

    envelope = encrypt(demo_message, demo_key)
    print("Envelope cifrado:", envelope.to_dict())

    decrypted = decrypt(envelope.ciphertext, envelope.nonce, demo_key)
    print("Mensagem decifrada:", decrypted)

    assert decrypted == demo_message
    print("OK: round-trip de cifragem/decifragem bem-sucedido.")

if __name__ == "__main__":
    main()