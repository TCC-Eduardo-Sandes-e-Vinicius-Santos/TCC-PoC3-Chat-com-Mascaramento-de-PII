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


@pytest.fixture
def shared_key() -> bytes:
    """Chave simétrica válida (32 bytes), derivada de um par de IDs fixo."""
    return crypto_aes.derive_shared_key("U-100", "U-200")
