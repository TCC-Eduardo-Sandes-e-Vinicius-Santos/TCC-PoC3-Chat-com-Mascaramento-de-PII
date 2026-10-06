import base64
import os
import random

import pytest

import crypto_aes
from crypto_aes import (
    CryptoAESError,
    EncryptedMessage,
    MessageIntegrityError,
    decrypt,
    derive_shared_key,
    encrypt,
)

# derive_shared_key()

def test_derive_shared_key_is_order_independent():
    key_ab = derive_shared_key("U-100", "U-200")
    key_ba = derive_shared_key("U-200", "U-100")
    assert key_ab == key_ba


def test_derive_shared_key_has_256_bits():
    key = derive_shared_key("U-100", "U-200")
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_shared_key_different_pairs_yield_different_keys():
    key_1 = derive_shared_key("U-100", "U-200")
    key_2 = derive_shared_key("U-100", "U-300")
    assert key_1 != key_2


@pytest.mark.parametrize("id_a,id_b", [("", "U-200"), ("U-100", ""), ("", "")])
def test_derive_shared_key_rejects_empty_ids(id_a, id_b):
    with pytest.raises(CryptoAESError):
        derive_shared_key(id_a, id_b)


def test_derive_shared_key_rejects_equal_ids():
    with pytest.raises(CryptoAESError):
        derive_shared_key("U-100", "U-100")

# Criptografia

def test_encrypt_decrypt_roundtrip_preserves_plaintext(shared_key):
    original = "Mensagem de teste, com acentuação e emoji 🔒."
    envelope = encrypt(original, shared_key)
    recovered = decrypt(envelope.ciphertext, envelope.nonce, shared_key)
    assert recovered == original


def test_encrypt_uses_a_fresh_random_nonce_each_call(shared_key):
    envelope_1 = encrypt("mesma mensagem", shared_key)
    envelope_2 = encrypt("mesma mensagem", shared_key)
    assert envelope_1.nonce != envelope_2.nonce
    assert envelope_1.ciphertext != envelope_2.ciphertext


def test_decrypt_with_wrong_key_raises_integrity_error(shared_key):
    envelope = encrypt("segredo", shared_key)
    wrong_key = os.urandom(32)
    with pytest.raises(MessageIntegrityError):
        decrypt(envelope.ciphertext, envelope.nonce, wrong_key)


def test_decrypt_rejects_malformed_base64(shared_key):
    with pytest.raises(CryptoAESError):
        decrypt("isto-nao-e-base64-valido!!", "tambem-nao", shared_key)


def test_decrypt_rejects_nonce_with_wrong_length(shared_key):
    envelope = encrypt("segredo", shared_key)
    short_nonce = base64.b64encode(b"curto").decode("ascii")
    with pytest.raises(CryptoAESError):
        decrypt(envelope.ciphertext, short_nonce, shared_key)


@pytest.mark.parametrize("bad_key", [b"muito-curta", os.urandom(16), os.urandom(64)])
def test_encrypt_rejects_key_with_wrong_size(bad_key):
    with pytest.raises(CryptoAESError):
        encrypt("mensagem", bad_key)


def test_encrypt_rejects_none_plaintext(shared_key):
    with pytest.raises(CryptoAESError):
        encrypt(None, shared_key)


# Mensagem


def test_encrypted_message_dict_roundtrip(shared_key):
    envelope = encrypt("mensagem", shared_key)
    rebuilt = EncryptedMessage.from_dict(envelope.to_dict())
    assert rebuilt == envelope


def test_encrypted_message_from_dict_missing_field_raises():
    with pytest.raises(CryptoAESError):
        EncryptedMessage.from_dict({"ciphertext": "abc"})

# Taxa de Detecção de Adulteração (Tamper Detection Rate)

def _flip_random_byte(data: bytes, rng: random.Random) -> bytes:
    """Inverte (XOR com valor != 0) um byte aleatório de `data`."""
    data = bytearray(data)
    index = rng.randrange(len(data))
    flip = rng.randrange(1, 256)
    data[index] ^= flip
    return bytes(data)


def measure_tamper_detection_rate(
    n_trials: int = 1000,
    target: str = "ciphertext",
    seed: int = 42,
) -> dict:
    """
    Executa `n_trials` tentativas de adulteração (bit-flipping) sobre o
    `ciphertext` ou o `nonce` de mensagens cifradas com AES-256-GCM, e mede
    a proporção corretamente rejeitada por `MessageIntegrityError`.

    Retorna um dicionário com as contagens brutas e a taxa calculada,
    reaproveitável tanto pelos testes automatizados quanto pelo script de
    medição usado para reportar a métrica na seção de Resultados.
    """
    assert target in {"ciphertext", "nonce"}

    rng = random.Random(seed)
    key = derive_shared_key("U-100", "U-200")

    detected = 0
    undetected_cases = []
    unexpected_errors = []

    for i in range(n_trials):
        plaintext = f"mensagem de teste número {i} com conteúdo variável {rng.random()}"
        envelope = encrypt(plaintext, key)

        if target == "ciphertext":
            raw = base64.b64decode(envelope.ciphertext)
            tampered_raw = _flip_random_byte(raw, rng)
            tampered_ciphertext = base64.b64encode(tampered_raw).decode("ascii")
            tampered_nonce = envelope.nonce
        else:
            raw = base64.b64decode(envelope.nonce)
            tampered_raw = _flip_random_byte(raw, rng)
            tampered_nonce = base64.b64encode(tampered_raw).decode("ascii")
            tampered_ciphertext = envelope.ciphertext

        try:
            decrypt(tampered_ciphertext, tampered_nonce, key)
        except MessageIntegrityError:
            detected += 1
        except CryptoAESError as exc:
            unexpected_errors.append((i, repr(exc)))
        else:
            undetected_cases.append(i)

    return {
        "target": target,
        "n_trials": n_trials,
        "detected": detected,
        "undetected": undetected_cases,
        "unexpected_errors": unexpected_errors,
        "tamper_detection_rate": detected / n_trials,
    }


@pytest.mark.parametrize("target", ["ciphertext", "nonce"])
def test_tamper_detection_rate_is_100_percent(target):
    """
    Métrica de avaliação: Taxa de Detecção de Adulteração.

    Executa 1000 tentativas de bit-flipping sobre o ciphertext/nonce e
    exige que TODAS sejam corretamente rejeitadas por MessageIntegrityError
    qualquer falha indica uma regressão crítica na garantia de
    integridade (US04).
    """
    result = measure_tamper_detection_rate(n_trials=1000, target=target)

    assert result["undetected"] == [], (
        f"{len(result['undetected'])} mensagem(ns) adulterada(s) foram "
        f"decifradas com sucesso quando deveriam ter sido rejeitadas: "
        f"{result['undetected']}"
    )
    assert result["unexpected_errors"] == [], (
        f"{len(result['unexpected_errors'])} tentativa(s) falharam por um "
        f"motivo diferente da tag GCM: {result['unexpected_errors']}"
    )
    assert result["tamper_detection_rate"] == 1.0


def test_tamper_detection_single_bit_flip_in_ciphertext_is_detected(shared_key):
    """Caso mínimo e determinístico: um único bit invertido já é suficiente
    para que o GCM rejeite a mensagem."""
    envelope = encrypt("mensagem sensível", shared_key)

    raw_ciphertext = bytearray(base64.b64decode(envelope.ciphertext))
    raw_ciphertext[0] ^= 0b0000_0001  # inverte o bit menos significativo
    tampered_ciphertext = base64.b64encode(bytes(raw_ciphertext)).decode("ascii")

    with pytest.raises(MessageIntegrityError):
        decrypt(tampered_ciphertext, envelope.nonce, shared_key)


def test_tamper_detection_single_bit_flip_in_nonce_is_detected(shared_key):
    envelope = encrypt("mensagem sensível", shared_key)

    raw_nonce = bytearray(base64.b64decode(envelope.nonce))
    raw_nonce[0] ^= 0b0000_0001
    tampered_nonce = base64.b64encode(bytes(raw_nonce)).decode("ascii")

    with pytest.raises(MessageIntegrityError):
        decrypt(envelope.ciphertext, tampered_nonce, shared_key)