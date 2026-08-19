"""Errors shown to a person, not raised at a service.

Each carries what to do next, because the alternative is a traceback and a
support question.
"""


class CliError(Exception):
    def __init__(self, message: str, *, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


class Aborted(CliError):
    """The operator declined a confirmation."""
