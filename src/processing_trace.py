"""Privacy-conscious trace of steps actually executed by the offline demo.

This is NOT an API, live monitoring, or a stream of network requests.
Only trusted static labels and aggregate counts should be recorded here.
Never pass raw event fields, paths, IP addresses, usernames or payloads.
"""


def record_step(trace, phase, description):
    """Append an executed processing step, or do nothing when tracing is disabled."""
    if trace is not None:
        trace.append({
            "etapa": len(trace) + 1,
            "fase": phase,
            "resultado": description,
        })
