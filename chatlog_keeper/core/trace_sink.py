"""No-op telemetry sink. The open-source build ships zero telemetry; this
module exists only so optional `from chatlog_keeper.core.trace_sink import emit`
calls resolve to a harmless no-op."""


def emit(*args, **kwargs):  # noqa: D401
    return None
