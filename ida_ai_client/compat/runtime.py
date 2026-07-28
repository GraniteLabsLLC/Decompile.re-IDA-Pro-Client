"""Detect the active IDA runtime before importing version-specific APIs."""

import re

import ida_kernwin


SUPPORTED_IDA_MAJORS = (8, 9)
MINIMUM_IDA_VERSION = (8, 3)
MAXIMUM_IDA_VERSION = (9, 3)


def get_ida_version():
    return str(ida_kernwin.get_kernel_version())


def get_ida_major():
    match = re.match(r"\s*(\d+)", get_ida_version())
    if not match:
        raise RuntimeError("Could not determine the IDA version")
    return int(match.group(1))


def get_ida_version_tuple():
    match = re.match(r"\s*(\d+)(?:\.(\d+))?", get_ida_version())
    if not match:
        raise RuntimeError("Could not determine the IDA version")
    return int(match.group(1)), int(match.group(2) or 0)


IDA_VERSION = get_ida_version()
IDA_MAJOR = get_ida_major()
IDA_VERSION_TUPLE = get_ida_version_tuple()


def is_supported_ida():
    return MINIMUM_IDA_VERSION <= IDA_VERSION_TUPLE <= MAXIMUM_IDA_VERSION


def require_supported_ida():
    if not is_supported_ida():
        raise RuntimeError(
            "Unsupported IDA version %s; supported versions are 8.3 through 9.3"
            % IDA_VERSION
        )
