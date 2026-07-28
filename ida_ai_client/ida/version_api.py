"""Select the IDA implementation while exposing one stable module contract."""

from ..compat.runtime import IDA_MAJOR, require_supported_ida


require_supported_ida()

if IDA_MAJOR == 8:
    from .versions import ida8 as version_api
else:
    from .versions import ida9 as version_api

__all__ = ["version_api"]
