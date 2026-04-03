import requests
import xml.etree.ElementTree as ET
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Config ────────────────────────────────────────────────────────────────────

PANORAMA_HOST = "your-panorama-hostname-or-ip"
USERNAME      = "your-username"
PASSWORD      = "your-password"
OUTPUT_FILE   = "panorama_full_export.json"

BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"


# ── Auth ──────────────────────────────────────────────────────────────────────

def get_api_key(host, username, password):
    """Log in to Panorama and return an API key."""
    response = requests.get(
        f"https://{host}/api/",
        params={"type": "keygen", "user": username, "password": password},
        verify=False,
    )
    response.raise_for_status()
    root = ET.fromstring(response.text)
    if root.attrib.get("status") != "success":
        raise Exception("Login failed. Check your username and password.")
    print("✅ Login successful.")
    return root.find(".//key").text


# ── Low-level API call ────────────────────────────────────────────────────────

def panorama_get(host, api_key, xpath):
    """Send a config GET request to Panorama and return the parsed XML root."""
    response = requests.get(
        f"https://{host}/api/",
        params={"type": "config", "action": "get", "xpath": xpath, "key": api_key},
        verify=False,
    )
    response.raise_for_status()
    root = ET.fromstring(response.text)
    if root.attrib.get("status") != "success":
        raise Exception(f"API call failed for xpath: {xpath}\nResponse: {response.text}")
    return root


# ── XML helpers ───────────────────────────────────────────────────────────────

def xml_text(element, tag, default=""):
    """Safely read the text of a child tag, return default if missing."""
    node = element.find(tag)
    return node.text if node is not None and node.text else default


def xml_members(element, tag):
    """Return a list of <member> texts inside a child tag."""
    parent = element.find(tag)
    if parent is None:
        return []
    return [m.text for m in parent.findall("member") if m.text]


def xml_tags(element):
    """Return the tag names applied to an object."""
    return xml_members(element, "tag")


def dg_xpath(dg_name, sub_path=""):
    """Build an xpath string scoped to a specific device group."""
    return f"{BASE_XPATH}/device-group/entry[@name='{dg_name}']{sub_path}"


# ── Device groups ─────────────────────────────────────────────────────────────

def get_device_group_names(host, api_key):
    """Return a list of all device group names."""
    root = panorama_get(host, api_key, f"{BASE_XPATH}/device-group")
    return [e.attrib["name"] for e in root.findall(".//device-group/entry")]


def get_device_group_hierarchy(host, api_key):
    """Return a dict mapping each device group name to its parent (or None)."""
    root = panorama_get(host, api_key, f"/config/readonly{BASE_XPATH}/device-group")
    hierarchy = {}
    for entry in root.findall(".//device-group/entry"):
        name = entry.attrib["name"]
        parent_node = entry.find("parent-dg")
        hierarchy[name] = parent_node.text if parent_node is not None else None
    return hierarchy


def get_devices_in_group(host, api_key, dg_name):
    """Return a list of dicts, one per firewall assigned to this device group."""
    root = panorama_get(host, api_key, dg_xpath(dg_name, "/devices"))
    devices = []
    for entry in root.findall(".//devices/entry"):
        vsys_list = [v.attrib["name"] for v in entry.findall(".//vsys/entry")]
        devices.append({
            "serial": entry.attrib["name"],
            "vsys":   vsys_list if vsys_list else ["vsys1"],
        })
    return devices


# ── Address objects ───────────────────────────────────────────────────────────

def get_address_objects(host, api_key, dg_name):
    """Return all address objects defined in the device group."""
    root = panorama_get(host, api_key, dg_xpath(dg_name, "/address"))
    objects = []
    for entry in root.findall(".//address/entry"):
        # Find which address type this object uses
        addr_type = "unknown"
        value     = ""
        for t in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
            node = entry.find(t)
            if node is not None:
                addr_type = t
                value     = node.text or ""
                break
        objects.append({
            "name":        entry.attrib["name"],
            "type":        addr_type,
            "value":       value,
            "description": xml_text(entry, "description"),
            "tags":        xml_tags(entry),
        })
    return objects


def get_address_groups(host, api_key, dg_name):
    """Return all address groups defined in the device group."""
    root = panorama_get(host, api_key, dg_xpath(dg_name, "/address-group"))
    groups = []
    for entry in root.findall(".//address-group/entry"):
        static_node  = entry.find("static")
        dynamic_node = entry.find("dynamic/filter")
        groups.append({
            "name":        entry.attrib["name"],
            "type":        "static" if static_node is not None else "dynamic",
            "members":     xml_members(entry, "static"),
            "filter":      dynamic_node.text if dynamic_node is not None else "",
            "description": xml_text(entry, "description"),
            "tags":        xml_tags(entry),
        })
    return groups


# ── Service objects ───────────────────────────────────────────────────────────

def get_service_objects(host, api_key, dg_name):
    """Return all service objects defined in the device group."""
    root = panorama_get(host, api_key, dg_xpath(dg_name, "/service"))
    services = []
    for entry in root.findall(".//service/entry"):
        protocol = "unknown"
        src_port = ""
        dst_port = ""
        for p in ("tcp", "udp", "sctp"):
            proto_node = entry.find(f"protocol/{p}")
            if proto_node is not None:
                protocol = p
                src_port = xml_text(proto_node, "source-port")
                dst_port = xml_text(proto_node, "port")
                break
        services.append({
            "name":        entry.attrib["name"],
            "protocol":    protocol,
            "src_port":    src_port,
            "dst_port":    dst_port,
            "description": xml_text(entry, "description"),
            "tags":        xml_tags(entry),
        })
    return services


def get_service_groups(host, api_key, dg_name):
    """Return all service groups defined in the device group."""
    root = panorama_get(host, api_key, dg_xpath(dg_name, "/service-group"))
    return [
        {
            "name":    entry.attrib["name"],
            "members": xml_members(entry, "members"),
            "tags":    xml_tags(entry),
        }
        for entry in root.findall(".//service-group/entry")
    ]


def get_tags(host, api_key, dg_name):
    """Return all tags defined in the device group."""
    root = panorama_get(host, api_key, dg_xpath(dg_name, "/tag"))
    return [
        {
            "name":     entry.attrib["name"],
            "color":    xml_text(entry, "color"),
            "comments": xml_text(entry, "comments"),
        }
        for entry in root.findall(".//tag/entry")
    ]


# ── Security rules ────────────────────────────────────────────────────────────

def parse_security_rules(root):
    """Parse security rule XML entries into a list of dicts."""
    rules = []
    for entry in root.findall(".//rules/entry"):
        # Security profile — could be a group or individual profiles
        profile_setting = {}
        ps = entry.find("profile-setting")
        if ps is not None:
            group_node = ps.find("group/member")
            if group_node is not None:
                profile_setting = {"type": "group", "name": group_node.text}
            else:
                profile_setting = {
                    "type":     "profiles",
                    "av":       xml_text(ps, "profiles/virus/member"),
                    "vuln":     xml_text(ps, "profiles/vulnerability/member"),
                    "url":      xml_text(ps, "profiles/url-filtering/member"),
                    "spyware":  xml_text(ps, "profiles/spyware/member"),
                }
        rules.append({
            "name":                  entry.attrib["name"],
            "rule_type":             xml_text(entry, "rule-type", "universal"),
            "description":           xml_text(entry, "description"),
            "tags":                  xml_tags(entry),
            "source_zones":          xml_members(entry, "from"),
            "destination_zones":     xml_members(entry, "to"),
            "source_addresses":      xml_members(entry, "source"),
            "destination_addresses": xml_members(entry, "destination"),
            "applications":          xml_members(entry, "application"),
            "services":              xml_members(entry, "service"),
            "action":                xml_text(entry, "action"),
            "profile_setting":       profile_setting,
            "log_setting":           xml_text(entry, "log-setting"),
            "disabled":              xml_text(entry, "disabled") == "yes",
        })
    return rules


def get_security_rules(host, api_key, dg_name, position="pre"):
    """
    Fetch security rules for a device group.
    position: 'pre' for pre-rulebase, 'post' for post-rulebase
    """
    sub = f"/{position}-rulebase/security"
    root = panorama_get(host, api_key, dg_xpath(dg_name, sub))
    return parse_security_rules(root)


# ── NAT rules ─────────────────────────────────────────────────────────────────

def parse_nat_rules(root):
    """Parse NAT rule XML entries into a list of dicts."""
    rules = []
    for entry in root.findall(".//rules/entry"):
        # Source translation — three possible types
        src_xlat = {}
        src_node = entry.find("source-translation")
        if src_node is not None:
            for stype in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"):
                st = src_node.find(stype)
                if st is not None:
                    src_xlat["type"] = stype
                    addr_node = st.find("translated-address")
                    if addr_node is not None:
                        # could be a list of members or a single text value
                        members = xml_members(st, "translated-address")
                        src_xlat["translated_address"] = members if members else addr_node.text
                    iface_node = st.find("interface-address/interface")
                    if iface_node is not None:
                        src_xlat["interface"] = iface_node.text
                    break

        # Destination translation
        dst_xlat = {}
        dst_node = entry.find("destination-translation")
        if dst_node is not None:
            dst_xlat = {
                "translated_address": xml_text(dst_node, "translated-address"),
                "translated_port":    xml_text(dst_node, "translated-port"),
            }

        rules.append({
            "name":                  entry.attrib["name"],
            "description":           xml_text(entry, "description"),
            "tags":                  xml_tags(entry),
            "source_zones":          xml_members(entry, "from"),
            "destination_zones":     xml_members(entry, "to"),
            "source_addresses":      xml_members(entry, "source"),
            "destination_addresses": xml_members(entry, "destination"),
            "services":              xml_members(entry, "service") or [xml_text(entry, "service")],
            "nat_type":              xml_text(entry, "nat-type", "ipv4"),
            "source_translation":    src_xlat,
            "destination_translation": dst_xlat,
            "disabled":              xml_text(entry, "disabled") == "yes",
        })
    return rules


def get_nat_rules(host, api_key, dg_name, position="pre"):
    """
    Fetch NAT rules for a device group.
    position: 'pre' for pre-rulebase, 'post' for post-rulebase
    """
    sub = f"/{position}-rulebase/nat"
    root = panorama_get(host, api_key, dg_xpath(dg_name, sub))
    return parse_nat_rules(root)


# ── Full extraction for one device group ──────────────────────────────────────

def fetch_device_group(host, api_key, dg_name, parent):
    """
    Pull everything for a single device group and return it as a dict.
    Each section is fetched independently — if one fails the rest still run.
    """
    print(f"    Fetching devices ...")
    devices = safe_fetch("devices",             get_devices_in_group,  host, api_key, dg_name)
    print(f"    Fetching address objects ...")
    addr_obj = safe_fetch("address objects",    get_address_objects,   host, api_key, dg_name)
    print(f"    Fetching address groups ...")
    addr_grp = safe_fetch("address groups",     get_address_groups,    host, api_key, dg_name)
    print(f"    Fetching service objects ...")
    svc_obj  = safe_fetch("service objects",    get_service_objects,   host, api_key, dg_name)
    print(f"    Fetching service groups ...")
    svc_grp  = safe_fetch("service groups",     get_service_groups,    host, api_key, dg_name)
    print(f"    Fetching tags ...")
    tags     = safe_fetch("tags",               get_tags,              host, api_key, dg_name)
    print(f"    Fetching pre-security rules ...")
    pre_sec  = safe_fetch("pre-security rules", get_security_rules,    host, api_key, dg_name, "pre")
    print(f"    Fetching post-security rules ...")
    post_sec = safe_fetch("post-security rules",get_security_rules,    host, api_key, dg_name, "post")
    print(f"    Fetching pre-NAT rules ...")
    pre_nat  = safe_fetch("pre-NAT rules",      get_nat_rules,         host, api_key, dg_name, "pre")
    print(f"    Fetching post-NAT rules ...")
    post_nat = safe_fetch("post-NAT rules",     get_nat_rules,         host, api_key, dg_name, "post")

    return {
        "name":               dg_name,
        "parent":             parent,
        "devices":            devices,
        "address_objects":    addr_obj,
        "address_groups":     addr_grp,
        "service_objects":    svc_obj,
        "service_groups":     svc_grp,
        "tags":               tags,
        "pre_security_rules": pre_sec,
        "post_security_rules":post_sec,
        "pre_nat_rules":      pre_nat,
        "post_nat_rules":     post_nat,
    }


def safe_fetch(label, fn, *args):
    """
    Call fn(*args) and return the result.
    If anything goes wrong, print a warning and return an empty list
    instead of crashing the whole script.
    """
    try:
        return fn(*args)
    except Exception as e:
        print(f"    ⚠️  Could not fetch {label}: {e}")
        return []


# ── Fetch all device groups ───────────────────────────────────────────────────

def fetch_all_device_groups(host, api_key):
    """Loop over every device group in Panorama and extract all data."""
    names     = get_device_group_names(host, api_key)
    hierarchy = get_device_group_hierarchy(host, api_key)

    print(f"\nFound {len(names)} device group(s). Starting extraction...\n")

    all_groups = []
    for i, name in enumerate(names, start=1):
        print(f"  [{i}/{len(names)}] Extracting device group: {name}")
        dg = fetch_device_group(host, api_key, name, hierarchy.get(name))
        all_groups.append(dg)

    return all_groups


# ── Summary + export ──────────────────────────────────────────────────────────

def print_summary(all_groups):
    """Print a human-readable summary of what was extracted."""
    print("\n" + "=" * 70)
    print(f"{'PANORAMA EXTRACTION SUMMARY':^70}")
    print("=" * 70)
    for dg in all_groups:
        print(f"\n  📁 Device Group : {dg['name']}")
        print(f"     Parent        : {dg['parent'] or 'None (top-level)'}")
        print(f"     Devices       : {len(dg['devices'])}")
        print(f"     ── Objects ──────────────────────")
        print(f"       Address Objects  : {len(dg['address_objects'])}")
        print(f"       Address Groups   : {len(dg['address_groups'])}")
        print(f"       Service Objects  : {len(dg['service_objects'])}")
        print(f"       Service Groups   : {len(dg['service_groups'])}")
        print(f"       Tags             : {len(dg['tags'])}")
        print(f"     ── Policies ─────────────────────")
        print(f"       Pre-Security     : {len(dg['pre_security_rules'])}")
        print(f"       Post-Security    : {len(dg['post_security_rules'])}")
        print(f"       Pre-NAT          : {len(dg['pre_nat_rules'])}")
        print(f"       Post-NAT         : {len(dg['post_nat_rules'])}")
    print("\n" + "=" * 70)


def export_to_json(all_groups, output_file):
    """Save the full extraction to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(all_groups, f, indent=2)
    print(f"\n✅ Full export saved to: {output_file}")


# ── Entry point ───────────────────────────────────────────────────────────────

# Step 1 — log in and get an API key
api_key = get_api_key(PANORAMA_HOST, USERNAME, PASSWORD)

# Step 2 — pull everything
all_groups = fetch_all_device_groups(PANORAMA_HOST, api_key)

# Step 3 — show summary and save
print_summary(all_groups)
export_to_json(all_groups, OUTPUT_FILE)
