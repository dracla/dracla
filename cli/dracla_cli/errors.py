"""CLI-facing errors.

These are printed to a human, not raised at a service, so they carry what to do
next rather than a stack trace.
"""


class CliError(Exception):
    """A failure the user can act on."""

    def __init__(self, message: str, *, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


class Aborted(CliError):
    """The user declined a confirmation."""
