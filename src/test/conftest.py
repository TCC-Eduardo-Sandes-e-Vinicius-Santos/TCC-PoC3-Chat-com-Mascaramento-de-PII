"""
Fixtures compartilhadas pelos testes da PoC3.
"""
from __future__ import annotations

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pytest

import crypto_aes

# Valores exclusivos para testes (32 bytes aleatórios fixos, em base64).
# NÃO usar em execução real: cada implantação gera o seu no .env.
TEST_HKDF_SALT = "dGVzdC1vbmx5LXNhbHQtcG9jMy0zMi1ieXRlcy1sb25nIQ=="
TEST_HKDF_INFO = "poc3-e2ee-key-v1-test"


@pytest.fixture(autouse=True)
def hkdf_env(monkeypatch, tmp_path):
    """
    Isola os testes do .env real do desenvolvedor: aponta o carregador para
    um caminho inexistente e define salt/info conhecidos via ambiente.
    """
    monkeypatch.setattr(crypto_aes, "DEFAULT_ENV_FILE", tmp_path / "inexistente.env")
    monkeypatch.setenv(crypto_aes.ENV_SALT, TEST_HKDF_SALT)
    monkeypatch.setenv(crypto_aes.ENV_INFO, TEST_HKDF_INFO)


@pytest.fixture
def shared_key() -> bytes:
    """Chave simétrica válida (32 bytes), derivada de um par de IDs fixo."""
    return crypto_aes.derive_shared_key("U-100", "U-200")
