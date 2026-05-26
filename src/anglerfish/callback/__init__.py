"""Stage 11 slice 11.4 honeytoken callback receiver.

A standalone FastAPI app the operator deploys at the public URL
embedded in generated AWS-key + SSH-key honeytokens. Attackers who
exfiltrate ``/root/.aws/credentials`` and run ``aws s3 ls`` against
the resulting key trigger an HTTPS request to ``/cb/<token_id>``;
the receiver logs the hit (registered source IP, callback source
IP, User-Agent, request path) and returns an AWS-style 403 so the
attacker sees a plausible ``InvalidAccessKeyId`` error.

The receiver process is isolated from the bridge + dashboard
processes - the only shared surface is the read-only SQLite
sessions DB (for the honeytoken lookup) and the local audit log.
Operators ship the receiver's audit log back to the main
Anglerfish host via their existing forwarder (rsync, syslog,
Splunk); the dashboard's audit-log tailer surfaces the events
through the standard ``/api/alerts`` + ``/api/honeytokens/callbacks``
endpoints.
"""

from __future__ import annotations

from anglerfish.callback.app import create_callback_app

__all__ = ["create_callback_app"]
