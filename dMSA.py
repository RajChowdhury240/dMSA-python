import ldap3
from ldap3 import Server, Connection, ALL, NTLM
import re
from uuid import uuid4
from collections import defaultdict

def test_is_excluded_sid(identity_reference, sid_cache, excluded_sids):
    if identity_reference in sid_cache:
        return sid_cache[identity_reference]

    if re.match(r'^S-\d-\d+(-\d+)+$', identity_reference):
        sid = identity_reference
    else:
        try:
            search_filter = f"(sAMAccountName={identity_reference.split('\\')[-1]})"
            conn.search(domain_base, search_filter, attributes=['objectSid'])
            if conn.entries:
                sid_bytes = conn.entries[0].objectSid.value
                sid = ldap3.utils.conv.sid_to_string(sid_bytes)
            else:
                print(f"Warning: Failed to translate {identity_reference} to SID.")
                sid_cache[identity_reference] = False
                return False
        except Exception as e:
            print(f"Error translating {identity_reference} to SID: {e}")
            sid_cache[identity_reference] = False
            return False

    is_excluded = sid in excluded_sids or sid.endswith("-519")
    sid_cache[identity_reference] = is_excluded
    return is_excluded

def get_bad_successor_ou_permissions():
    server = Server('ldap://YOUR_DOMAIN_CONTROLLER', get_info=ALL)
    conn = Connection(server, user='DOMAIN\\USERNAME', password='PASSWORD', authentication=NTLM, auto_bind=True)
    domain_base = server.info.other['defaultNamingContext'][0]

    sid_cache = {}

    domain_sid = server.info.other['objectSid'][0]
    excluded_sids = [
        f"{domain_sid}-512",  # Domain Admins
        "S-1-5-32-544",       # Builtin Administrators
        "S-1-5-18"            # Local SYSTEM
    ]

    relevant_object_types = {
        "00000000-0000-0000-0000-000000000000": "All Objects",
        "0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount"
    }

    relevant_rights = ["CreateChild", "GenericAll", "WriteDACL", "WriteOwner"]

    allowed_identities = defaultdict(list)

    conn.search(
        search_base=domain_base,
        search_filter='(objectClass=organizationalUnit)',
        search_scope=ldap3.SUBTREE,
        attributes=['distinguishedName', 'ntSecurityDescriptor']
    )

    for entry in conn.entries:
        ou_dn = entry.distinguishedName.value
        nt_security_descriptor = entry.ntSecurityDescriptor.raw_values[0] if entry.ntSecurityDescriptor else None

        if not nt_security_descriptor:
            continue

        try:
            sd = ldap3.utils.security_descriptor.SecurityDescriptor(nt_security_descriptor)
        except Exception as e:
            print(f"Error parsing security descriptor for {ou_dn}: {e}")
            continue

        for ace in sd.dacl.aces:
            if ace['AceType'] != 0:  # 0 = ACCESS_ALLOWED_ACE_TYPE
                continue

            rights = ace['Ace']['Mask']
            object_type = str(ace['Ace'].get('ObjectType', ''))

            has_relevant_rights = False
            for right in relevant_rights:
                if right in ["CreateChild", "GenericAll", "WriteDACL", "WriteOwner"]:
                    # Map rights to their AD bit flags (simplified; adjust as needed)
                    if right == "CreateChild" and (rights & 0x1):  # ADS_RIGHT_DS_CREATE_CHILD
                        has_relevant_rights = True
                    elif right == "GenericAll" and (rights & 0xF01FF):  # FULL_CONTROL
                        has_relevant_rights = True
                    elif right == "WriteDACL" and (rights & 0x40000):  # ADS_RIGHT_DS_WRITE_DACL
                        has_relevant_rights = True
                    elif right == "WriteOwner" and (rights & 0x80000):  # ADS_RIGHT_DS_WRITE_OWNER
                        has_relevant_rights = True

            if not has_relevant_rights:
                continue

            if object_type not in relevant_object_types:
                continue

            identity = ace['Ace']['Sid']
            if test_is_excluded_sid(identity, sid_cache, excluded_sids):
                continue

            allowed_identities[identity].append(ou_dn)

        owner = sd.owner
        if not test_is_excluded_sid(owner, sid_cache, excluded_sids):
            allowed_identities[owner].append(ou_dn)

    results = []
    for identity, ous in allowed_identities.items():
        results.append({
            'Identity': identity,
            'OUs': ous
        })

    conn.unbind()
    return results

if __name__ == "__main__":
    results = get_bad_successor_ou_permissions()
    for result in results:
        print(f"Identity: {result['Identity']}")
        print(f"OUs: {', '.join(result['OUs'])}")
        print()
