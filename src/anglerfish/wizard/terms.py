"""Legal / ethical terms text displayed by the first-boot wizard.

A single constant kept in its own module so the wizard's logic
modules stay free of large blocks of prose and so the text is easy to
tweak without rebuilding the package.
"""

from __future__ import annotations

__all__ = ["TERMS"]


TERMS: str = """\
ANGLERFISH AI — TERMS OF RESPONSIBLE USE

By proceeding past this screen you affirm each of the following:

1. You are operating this honeypot on a network you OWN, or on a
   network on which you have EXPLICIT, WRITTEN AUTHORISATION from
   the network's owner to deploy a deceptive system. Honeypots
   deployed on third-party networks may constitute unauthorised
   access, wiretapping, or computer fraud in your jurisdiction.

2. You are responsible for compliance with all applicable laws and
   the acceptable-use policies of your hosting provider, network
   operator, registrar, and IP-block assignee.

3. Captured data (commands, payloads, credentials) is sensitive and
   may include real credentials submitted by misconfigured automated
   scanners. You will treat it as such. The credential database is
   encrypted at rest; do not export plaintext copies.

4. Anglerfish AI is provided "AS IS", with no warranty of any kind.

5. Sessions involving traffic that appears to come from a vulnerable
   third party (open relays, compromised home routers) should be
   reviewed before any retaliatory or active response.

If you cannot affirm every one of these points, decline below and
shut down the system.
"""
