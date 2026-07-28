"""IDA 8 implementations for APIs removed or changed in IDA 9."""

import idaapi
import idautils
import ida_struct
import ida_typeinf


def pointer_size():
    info = idaapi.get_inf_structure()
    return 8 if info.is_64bit() else 4


def _parse_member_type(type_string):
    tif = ida_typeinf.tinfo_t()
    declaration = "%s __member;" % type_string.rstrip(";")
    if ida_typeinf.parse_decl(tif, None, declaration, ida_typeinf.PT_SIL):
        return tif
    return None


def modify_struct_members(struct_name, modified_members, plugin_name):
    sid = ida_struct.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        print("[%s]   Struct '%s' not found for modification" % (plugin_name, struct_name))
        return 0

    sptr = ida_struct.get_struc(sid)
    if sptr is None:
        return 0

    count = 0
    for modification in modified_members:
        member_name = modification.get("name", "")
        type_string = (modification.get("type") or "").strip()
        new_name = (modification.get("new_name") or "").strip()
        if not member_name or (not type_string and not new_name):
            continue

        member = ida_struct.get_member_by_name(sptr, member_name)
        if member is None:
            continue

        offset = member.soff
        applied = False
        if type_string:
            tif = _parse_member_type(type_string)
            if tif is None:
                print(
                    "[%s]   Could not parse type '%s' for member '%s'"
                    % (plugin_name, type_string, member_name)
                )
            else:
                flags = ida_struct.SET_MEMTI_COMPATIBLE | ida_struct.SET_MEMTI_USERTI
                result = ida_struct.set_member_tinfo(sptr, member, 0, tif, flags)
                if result not in (ida_struct.SMT_OK, ida_struct.SMT_KEEP):
                    flags = ida_struct.SET_MEMTI_MAY_DESTROY | ida_struct.SET_MEMTI_USERTI
                    result = ida_struct.set_member_tinfo(sptr, member, 0, tif, flags)
                applied = result in (ida_struct.SMT_OK, ida_struct.SMT_KEEP)

        if new_name and new_name != member_name:
            applied = ida_struct.set_member_name(sptr, offset, new_name) or applied

        if applied:
            count += 1

    if count:
        ida_struct.save_struc(sptr, True)
    return count


def _member_type(member):
    tif = ida_typeinf.tinfo_t()
    if ida_struct.get_or_guess_member_tinfo(tif, member):
        return str(tif)
    return "DWORD"


def _struct_dict(sid, name, member_limit=None):
    sptr = ida_struct.get_struc(sid)
    if sptr is None:
        return None

    members = []
    for offset, member_name, _size in idautils.StructMembers(sid):
        if member_limit is not None and len(members) >= member_limit:
            break
        member = ida_struct.get_member(sptr, offset)
        members.append(
            {
                "name": member_name or "field_%X" % offset,
                "type": _member_type(member) if member is not None else "DWORD",
                "offset": offset,
            }
        )
    return {
        "name": name,
        "size": ida_struct.get_struc_size(sptr),
        "members": members,
    }


def get_all_structs(plugin_name):
    structs = []
    try:
        for _ordinal, sid, name in idautils.Structs():
            struct = _struct_dict(sid, name)
            if struct is not None:
                structs.append(struct)
    except Exception as exc:
        print("[%s] get_all_structs: %s" % (plugin_name, exc))
    return structs


def lookup_struct(name, member_limit):
    sid = ida_struct.get_struc_id(name)
    if sid == idaapi.BADADDR:
        return None
    return _struct_dict(sid, name, member_limit)
