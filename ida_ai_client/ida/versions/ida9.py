"""IDA 9 implementations for APIs removed or changed since IDA 8."""

import ida_typeinf


def pointer_size():
    import idaapi

    return 8 if idaapi.inf_is_64bit() else 4


def modify_struct_members(struct_name, modified_members, plugin_name):
    count = 0
    til = ida_typeinf.get_idati()

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, struct_name) or not tif.is_struct():
        print("[%s]   Struct '%s' not found for modification" % (plugin_name, struct_name))
        return 0

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return 0

    changed = False
    for modification in modified_members:
        member_name = modification.get("name", "")
        type_string = (modification.get("type") or "").strip()
        new_name = (modification.get("new_name") or "").strip()
        if not member_name or (not type_string and not new_name):
            continue

        for index in range(udt.size()):
            member = udt[index]
            if member.name != member_name:
                continue

            applied = False
            if type_string:
                new_tif = ida_typeinf.tinfo_t()
                if ida_typeinf.parse_decl(
                    new_tif,
                    None,
                    type_string.rstrip(";") + ";",
                    ida_typeinf.PT_SIL,
                ):
                    member.type = new_tif
                    applied = True
                else:
                    print(
                        "[%s]   Could not parse type '%s' for member '%s'"
                        % (plugin_name, type_string, member_name)
                    )
            if new_name and new_name != member.name:
                member.name = new_name
                applied = True
            if applied:
                changed = True
                count += 1
            break

    if changed:
        try:
            updated = ida_typeinf.tinfo_t()
            if updated.create_udt(udt, ida_typeinf.BTF_STRUCT):
                ordinal = ida_typeinf.get_type_ordinal(til, struct_name)
                if ordinal:
                    updated.set_numbered_type(
                        til,
                        ordinal,
                        ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE,
                        struct_name,
                    )
        except Exception as exc:
            print("[%s] modify_struct_members write-back: %s" % (plugin_name, exc))
    return count


def _struct_dict(name, tif, member_limit=None):
    if not tif or not tif.is_struct():
        return None
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return None

    members = []
    limit = udt.size()
    if member_limit is not None:
        limit = min(limit, member_limit)
    for index in range(limit):
        member = udt[index]
        offset = member.offset // 8
        members.append(
            {
                "name": member.name or "field_%X" % offset,
                "type": str(member.type) if member.type else "DWORD",
                "offset": offset,
            }
        )
    return {"name": name, "size": tif.get_size(), "members": members}


def get_all_structs(plugin_name):
    structs = []
    try:
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_qty(til)
        for ordinal in range(1, count + 1):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if not name:
                continue
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            struct = _struct_dict(name, tif)
            if struct is not None:
                structs.append(struct)
    except Exception as exc:
        print("[%s] get_all_structs: %s" % (plugin_name, exc))
    return structs


def lookup_struct(name, member_limit):
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        return None
    return _struct_dict(name, tif, member_limit)
