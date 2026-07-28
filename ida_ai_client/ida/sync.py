"""
sync.py — Helper for running IDA database operations on the main thread.
"""

import idaapi


def run_on_main(func, *args, **kwargs):
    """Run func(*args, **kwargs) on IDA's main thread and return its result."""
    result  = [None]
    exc_box = [None]

    def _wrapper():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exc_box[0] = e
        return 0

    idaapi.execute_sync(_wrapper, idaapi.MFF_WRITE)

    if exc_box[0] is not None:
        raise exc_box[0]

    return result[0]
