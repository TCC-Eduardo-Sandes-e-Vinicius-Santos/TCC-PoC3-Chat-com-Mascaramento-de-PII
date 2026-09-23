import base64
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import crypto_aes  # noqa: E402


class TestDeriveSharedKey:
    def test_key_has_256_bits(self):
        key = crypto_aes.derive_shared_key("U-100", "U-200")
        assert isinstance(key, bytes)
        assert len(key) == 32  # AES-256

    def test_is_symmetric_regardless_of_argument_order(self):
        key_ab = crypto_aes.derive_shared_key("U-100", "U-200")
        key_ba = crypto_aes.derive_shared_key("U-200", "U-100")
        assert key_ab == key_ba

    def test_is_deterministic_across_calls(self):
        key_1 = crypto_aes.derive_shared_key("U-100", "U-200")
        key_2 = crypto_aes.derive_shared_key("U-100", "U-200")
        assert key_1 == key_2

    def test_different_pairs_produce_different_keys(self):
        key_ab = crypto_aes.derive_shared_key("U-100", "U-200")
        key_ac = crypto_aes.derive_shared_key("U-100", "U-300")
        assert key_ab != key_ac

    @pytest.mark.parametrize("id_a, id_b", [("", "U-200"), ("U-100", ""), ("", "")])
    def test_rejects_empty_ids(self, id_a, id_b):
        with pytest.raises(crypto_aes.CryptoAESError):
            crypto_aes.derive_shared_key(id_a, id_b)

    def test_rejects_identical_ids(self):
        with pytest.raises(crypto_aes.CryptoAESError):
            crypto_aes.derive_shared_key("U-100", "U-100")


@pytest.fixture
def key() -> bytes:
    return crypto_aes.derive_shared_key("U-100", "U-200")


class TestEncryptDecryptRoundTrip:
    @pytest.mark.parametrize(
        "plaintext",
        [
            "Olá, tudo bem?",
            "Mensagem com acentuação, cedilha e emoji: ção çã 🔒🚀",
            "",  # string vazia é uma entrada válida
            "x" * 5000,  # mensagem longa
            "Meu CPF é [DADO_SENSÍVEL_REMOVIDO]",  # formato típico pós-DLP
        ],
    )
    def test_decrypt_returns_original_plaintext(self, key, plaintext):
        envelope = crypto_aes.encrypt(plaintext, key)
        recovered = crypto_aes.decrypt(envelope.ciphertext, envelope.nonce, key)
        assert recovered == plaintext

    def test_ciphertext_and_nonce_are_valid_base64(self, key):
        envelope = crypto_aes.encrypt("mensagem qualquer", key)
        # não deve levantar exceção:
        base64.b64decode(envelope.ciphertext, validate=True)
        base64.b64decode(envelope.nonce, validate=True)

    def test_nonce_and_ciphertext_change_on_every_call(self, key):
        envelope_1 = crypto_aes.encrypt("mesma mensagem", key)
        envelope_2 = crypto_aes.encrypt("mesma mensagem", key)
        assert envelope_1.nonce != envelope_2.nonce
        assert envelope_1.ciphertext != envelope_2.ciphertext

    def test_to_dict_and_from_dict_round_trip(self, key):
        envelope = crypto_aes.encrypt("mensagem", key)
        rebuilt = crypto_aes.EncryptedMessage.from_dict(envelope.to_dict())
        recovered = crypto_aes.decrypt(rebuilt.ciphertext, rebuilt.nonce, key)
        assert recovered == "mensagem"

    def test_from_dict_rejects_missing_field(self):
        with pytest.raises(crypto_aes.CryptoAESError):
            crypto_aes.EncryptedMessage.from_dict({"ciphertext": "abc"})


class TestIntegrityAndTampering:
    def test_tampered_ciphertext_is_rejected(self, key):
        envelope = crypto_aes.encrypt("mensagem original", key)

        raw = bytearray(base64.b64decode(envelope.ciphertext))
        raw[0] ^= 0xFF  # inverte o primeiro byte do ciphertext
        tampered_ciphertext = base64.b64encode(bytes(raw)).decode("ascii")

        with pytest.raises(crypto_aes.MessageIntegrityError):
            crypto_aes.decrypt(tampered_ciphertext, envelope.nonce, key)

    def test_wrong_key_is_rejected(self, key):
        envelope = crypto_aes.encrypt("mensagem original", key)
        wrong_key = crypto_aes.derive_shared_key("U-100", "U-999")

        with pytest.raises(crypto_aes.MessageIntegrityError):
            crypto_aes.decrypt(envelope.ciphertext, envelope.nonce, wrong_key)

    def test_wrong_nonce_is_rejected(self, key):
        envelope = crypto_aes.encrypt("mensagem original", key)
        other_envelope = crypto_aes.encrypt("outra mensagem", key)

        with pytest.raises(crypto_aes.MessageIntegrityError):
            crypto_aes.decrypt(envelope.ciphertext, other_envelope.nonce, key)

    def test_invalid_base64_raises_crypto_aes_error(self, key):
        with pytest.raises(crypto_aes.CryptoAESError):
            crypto_aes.decrypt("isto não é base64 válido!!", "também não", key)


class TestKeyValidation:
    @pytest.mark.parametrize(
        "bad_key",
        [b"muito curta", b"x" * 16, b"x" * 64, "chave-nao-e-bytes", None],
    )
    def test_encrypt_rejects_invalid_key(self, bad_key):
        with pytest.raises(crypto_aes.CryptoAESError):
            crypto_aes.encrypt("mensagem", bad_key)

    @pytest.mark.parametrize(
        "bad_key",
        [b"muito curta", b"x" * 16, b"x" * 64, "chave-nao-e-bytes", None],
    )
    def test_decrypt_rejects_invalid_key(self, key, bad_key):
        envelope = crypto_aes.encrypt("mensagem", key)
        with pytest.raises(crypto_aes.CryptoAESError):
            crypto_aes.decrypt(envelope.ciphertext, envelope.nonce, bad_key)


class TestInteroperability:
    def test_envelope_is_decryptable_with_raw_aesgcm(self, key):
        envelope = crypto_aes.encrypt("mensagem interoperável", key)

        raw_ciphertext = base64.b64decode(envelope.ciphertext)
        raw_nonce = base64.b64decode(envelope.nonce)

        plaintext = AESGCM(key).decrypt(raw_nonce, raw_ciphertext, None)
        assert plaintext.decode("utf-8") == "mensagem interoperável"
