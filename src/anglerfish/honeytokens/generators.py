"""AWS + SSH honeytoken generators (Stage 11 slice 11.1).

Each generator returns a :class:`Honeytoken` ready for the slice
11.2 registry insert and the slice 11.3 fakefs_overlay merge.
The Stage 11 design's "Token types" decision locked AWS access
keys + SSH keypairs as v1; DB connection strings + API tokens
defer to v1.1.

Generators take an optional ``id_factory`` so tests can produce
deterministic IDs without monkey-patching :func:`secrets.token_bytes`.
Production callers pass nothing; the default factory is
:func:`new_lookup_id` which uses :func:`secrets.token_bytes`.
"""

from __future__ import annotations

import secrets
import string
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from anglerfish.honeytokens.schema import Honeytoken, new_lookup_id

__all__ = ["HoneytokenGenerator"]


_DEFAULT_AWS_PATH = "/root/.aws/credentials"
_DEFAULT_SSH_PATH = "/root/.ssh/id_rsa"

# AWS secret-access-key alphabet (uppercase + lowercase + digits +
# / and +; 40 chars total in real keys). The secret never round-
# trips to the registry - the callback receiver only cares about
# the access-key-ID half - but it has to LOOK valid or attackers
# notice immediately.
_AWS_SECRET_ALPHABET = string.ascii_letters + string.digits + "/+"


class HoneytokenGenerator:
    """Stateless generator for AWS access keys and SSH keypairs.

    Construct once at bridge startup with the operator's
    ``callback_base_url``; reuse for every generation. Both
    methods are pure: same ``id_factory`` + ``clock`` outputs
    reproducible :class:`Honeytoken` instances.
    """

    def __init__(
        self,
        *,
        callback_base_url: str,
        id_factory: Callable[[], str] = new_lookup_id,
        secret_factory: Callable[[], str] | None = None,
        clock: Callable[[], datetime] | None = None,
        ssh_key_factory: Callable[[], ed25519.Ed25519PrivateKey] | None = None,
    ) -> None:
        if not callback_base_url:
            raise ValueError("callback_base_url cannot be empty")
        # Strip any trailing slash so token URLs are not double-slashed.
        self._callback_base_url = callback_base_url.rstrip("/")
        self._id_factory = id_factory
        self._secret_factory = secret_factory if secret_factory is not None else _random_aws_secret
        self._clock = clock if clock is not None else _utcnow
        self._ssh_key_factory = (
            ssh_key_factory if ssh_key_factory is not None else ed25519.Ed25519PrivateKey.generate
        )

    def generate_aws(
        self,
        *,
        source_ip: str | None = None,
        session_id: UUID | None = None,
        placed_at: str = _DEFAULT_AWS_PATH,
    ) -> Honeytoken:
        """Generate an AWS access-key honeytoken.

        Payload shape (INI):

        ``[default]``
        ``aws_access_key_id = AKIA<16-char-id>``
        ``aws_secret_access_key = <40-char-random>``
        ``region = us-east-1``

        The ``id`` field round-trips: the callback receiver
        extracts the 16 chars after ``AKIA`` from incoming
        requests and queries the registry by it.
        """
        lookup_id = self._id_factory()
        secret = self._secret_factory()
        payload = (
            "[default]\n"
            f"aws_access_key_id = AKIA{lookup_id}\n"
            f"aws_secret_access_key = {secret}\n"
            "region = us-east-1\n"
        )
        return Honeytoken(
            id=lookup_id,
            kind="aws",
            payload=payload,
            callback_url=self._aws_callback_url(lookup_id),
            placed_at=placed_at,
            source_ip=source_ip,
            session_id=session_id,
            created_at=self._clock(),
        )

    def generate_ssh(
        self,
        *,
        source_ip: str | None = None,
        session_id: UUID | None = None,
        placed_at: str = _DEFAULT_SSH_PATH,
    ) -> Honeytoken:
        """Generate an Ed25519 SSH-keypair honeytoken.

        Payload is the PEM-encoded private key (what the
        attacker exfiltrates from ``~/.ssh/id_rsa``). The
        public-key comment carries ``honeytoken-<id>`` so the
        operator can grep pastebin / Shodan for the comment
        to identify the install.
        """
        lookup_id = self._id_factory()
        private_key = self._ssh_key_factory()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        public_bytes = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .decode("ascii")
        )
        public_with_comment = f"{public_bytes} honeytoken-{lookup_id}\n"
        # Stash the public key inside the private payload so the
        # tests + operator triage can pull it out without re-
        # parsing PEM. The format is a header line above the
        # PEM block, ignored by ssh-keygen / openssh on read.
        payload = f"# honeytoken-public-key: {public_with_comment.strip()}\n{private_pem}"
        return Honeytoken(
            id=lookup_id,
            kind="ssh_key",
            payload=payload,
            callback_url=self._ssh_callback_url(lookup_id),
            placed_at=placed_at,
            source_ip=source_ip,
            session_id=session_id,
            created_at=self._clock(),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _aws_callback_url(self, lookup_id: str) -> str:
        return f"{self._callback_base_url}/cb/{lookup_id}"

    def _ssh_callback_url(self, lookup_id: str) -> str:
        # SSH callbacks share the /cb/{id} path; operators looking
        # for the public-key comment in pastes find the lookup ID
        # and hit the same endpoint manually for triage.
        return f"{self._callback_base_url}/cb/{lookup_id}"


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _random_aws_secret() -> str:
    """Generate a 40-char AWS-secret-shaped string. Never round-trips."""
    return "".join(secrets.choice(_AWS_SECRET_ALPHABET) for _ in range(40))
