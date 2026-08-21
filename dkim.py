"""Parse and score DKIM public key records.

Scoring follows RFC 8301: RSA keys must be at least 1024 bits and 2048 is
recommended. Ed25519 (RFC 8463) keys are 256 bits but score as strong, since
the length is fixed by the algorithm and is not comparable to an RSA modulus.
"""

import base64

try:
    from cryptography.hazmat.primitives.serialization import load_der_public_key
except ImportError:
    load_der_public_key = None


KEY_LENGTH_SCORES = {
    "weak": 1,       # RSA below 1024 bits
    "compliant": 2,  # RSA 1024 to 2047 bits
    "strong": 3,     # RSA 2048 bits or more, or ed25519
}


def parse_tags(record):
    """Split a DKIM record into its tag-value pairs."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip()] = value.strip()
    return tags


def get_key_bits(tags):
    """Return the key length in bits, or None if it cannot be determined."""
    p = tags.get("p", "")
    if not p:
        return None

    if tags.get("k", "rsa").lower() == "ed25519":
        return 256

    if load_der_public_key is None:
        return None

    try:
        # The p= tag holds a DER-encoded public key in base64. Padding is
        # often omitted in published records, so restore it before decoding.
        key_bytes = base64.b64decode(p + "=" * (-len(p) % 4))
        return load_der_public_key(key_bytes).key_size
    except Exception:
        return None


def score_dkim(record):
    """Score a DKIM record and return its observable properties."""
    if not record:
        return {
            "key_type": None,
            "key_bits": None,
            "key_length_score": None,
            "revoked": None,
            "testing_mode": None,
        }

    tags = parse_tags(record)

    # RFC 6376 an empty p= revokes the key, and t=y puts the
    # record in testing mode, asking receivers to ignore verification failures.
    revoked = tags.get("p", "") == ""
    testing_mode = "y" in tags.get("t", "").split(":")

    key_type = tags.get("k", "rsa").lower()
    key_bits = None if revoked else get_key_bits(tags)

    if key_bits is None:
        key_length_score = None
    elif key_type == "ed25519":
        key_length_score = KEY_LENGTH_SCORES["strong"]
    elif key_bits < 1024:
        key_length_score = KEY_LENGTH_SCORES["weak"]
    elif key_bits < 2048:
        key_length_score = KEY_LENGTH_SCORES["compliant"]
    else:
        key_length_score = KEY_LENGTH_SCORES["strong"]

    return {
        "key_type": key_type,
        "key_bits": key_bits,
        "key_length_score": key_length_score,
        "revoked": revoked,
        "testing_mode": testing_mode,
    }