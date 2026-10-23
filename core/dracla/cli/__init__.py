"""DraCLA client entrypoint. Core imports do not initialize client libraries."""


def main(argv=None):
    from .app import main as dispatch
    return dispatch(argv)
