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
(em especial: não há handshake de identidade autenticado, e o segredo
POC3_HKDF_SALT é compartilhado por todos os clientes).

Configuração (variáveis de ambiente ou arquivo .env na raiz do projeto):
  - POC3_HKDF_SALT: segredo de alta entropia (>= 32 bytes, em base64),
    distribuído apenas aos clientes. Nunca deve existir no host do broker.
  - POC3_HKDF_INFO: rótulo de contexto/versão da derivação (não secreto).
Veja .env.example.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE: Final[int] = 12
_KEY_SIZE:   Final[int] = 32
_MIN_SALT_SIZE: Final[int] = 32

ENV_SALT: Final[str] = "POC3_HKDF_SALT"
ENV_INFO: Final[str] = "POC3_HKDF_INFO"
DEFAULT_ENV_FILE: Final[Path] = Path(__file__).resolve().parent.parent / ".env"


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


def load_env_file(path: Optional[Path] = None) -> None:
    """
    Carrega pares CHAVE=VALOR de um arquivo .env para os.environ, sem
    sobrescrever variáveis já definidas no ambiente. Implementação mínima,
    só com a biblioteca padrão, para não acrescentar dependência ao projeto.
    Linhas vazias e comentários (#) são ignorados; aspas simples ou duplas
    em volta do valor são removidas. Se o arquivo não existir, nada é feito.
    """
    env_path = Path(path) if path is not None else DEFAULT_ENV_FILE
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name:
            os.environ.setdefault(name, value)


def _load_kdf_params() -> tuple[bytes, bytes]:
    """
    Lê salt e info da derivação a partir do ambiente (carregando o .env, se
    existir). Falha de forma fechada: sem segredo configurado, nenhuma chave
    é derivada, em vez de cair silenciosamente num valor padrão conhecido.
    """
    load_env_file()

    salt_b64 = os.environ.get(ENV_SALT, "").strip()
    info = os.environ.get(ENV_INFO, "").strip()

    if not salt_b64:
        raise CryptoAESError(
            f"{ENV_SALT} não configurado. Gere um valor com "
            "`python3 -c \"import secrets, base64; "
            "print(base64.b64encode(secrets.token_bytes(32)).decode())\"` "
            "e defina-o no .env (veja .env.example)."
        )
    if not info:
        raise CryptoAESError(f"{ENV_INFO} não configurado (veja .env.example).")

    try:
        salt = base64.b64decode(salt_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoAESError(f"{ENV_SALT} não é um base64 válido: {exc}") from exc

    if len(salt) < _MIN_SALT_SIZE:
        raise CryptoAESError(
            f"{ENV_SALT} muito curto: {len(salt)} bytes "
            f"(mínimo {_MIN_SALT_SIZE} bytes aleatórios)."
        )

    return salt, info.encode("utf-8")


def derive_shared_key(id_a: str, id_b: str) -> bytes:
    """
    Deriva uma chave simétrica de 256 bits compartilhada exclusivamente pelo
    par (id_a, id_b), via HKDF-SHA256. Os IDs são ordenados antes da derivação,
    então o par produz sempre a mesma chave, independentemente de quem é
    remetente e quem é destinatário na chamada.

    O salt (secreto, alta entropia) e o info vêm de POC3_HKDF_SALT e
    POC3_HKDF_INFO. Sem o salt, conhecer os IDs (que trafegam em claro no
    Kafka) não basta para derivar a chave.
    """
    if not id_a or not id_b:
        raise CryptoAESError(
            "Os dois IDs (id_a, id_b) são obrigatórios e não podem ser vazios."
        )
    if id_a == id_b:
        raise CryptoAESError("id_a e id_b devem ser IDs de usuários distintos.")

    salt, info = _load_kdf_params()

    ordered_ids = sorted([str(id_a), str(id_b)])
    ikm = "|".join(ordered_ids).encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def encrypt(plaintext: str, key: bytes) -> EncryptedMessage:
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