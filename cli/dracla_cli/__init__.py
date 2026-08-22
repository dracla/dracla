"""dracla — provisioning and reporting for DraCLA maintainers.

Runs on the administrator's machine with their own GitHub credentials. DraCLA
the service holds no provisioning privilege at any point (design D11), which is
why this exists as a CLI rather than a hosted flow.

Scope is deliberately narrow (§6.10.3): install provisions repositories and the
workflow. Recipient, scope, policy text, and the agreement are configured in the
portal, where each becomes an attributable event.
"""

__version__ = "0.0.1"
