from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import InvalidRequestError


def validate_intune_csr(pem: str) -> None:
    try:
        request = x509.load_pem_x509_csr(pem.encode("ascii"))
        public_key = request.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
            raise InvalidRequestError("CertificateSigningRequest must use RSA 2048")
        if request.signature_hash_algorithm.name != "sha256":
            raise InvalidRequestError("CertificateSigningRequest must use SHA-256")
        public_key.verify(
            request.signature,
            request.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidRequestError:
        raise
    except (ValueError, TypeError, UnicodeError) as exc:
        raise InvalidRequestError("CertificateSigningRequest is not valid PEM PKCS#10") from exc
    except Exception as exc:
        raise InvalidRequestError("CertificateSigningRequest signature is invalid") from exc
