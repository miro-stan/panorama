import requests
import xml.etree.ElementTree as ET
import urllib3
import json

# Disable SSL warnings (optional, for self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_panorama_api_key(hostname: str, username: str, password: str) -> str:
    """Generate an API key from Panorama credentials."""
    url = f"https://{hostname}/api/"
    params = {
        "type": "keygen",
        "user": username,
        "password": password,
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()

    root = ET.fromstring(response.text)
    if root.attrib.get("status") != "success":
        raise Exception("Authentication failed. Check your credentials.")

    return root.find(".//key").text


def get_device_groups(hostname: str, api_key: str) -> list[dict]:
    """Fetch all device groups from Panorama."""
    url = f"https://{hostname}/api/"
    params = {
        "type": "config",
        "action": "get",
        "xpath": "/config/devices/entry[@name='localhost.localdomain']/device-group",
        "key": api_key,
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()

    root = ET.fromstring(response.text)
    if root.attrib.get("status") != "success":
        raise Exception(f"Failed to retrieve device groups: {response.text}")

    device_groups = []
    for entry in root.findall(".//device-group/entry"):
        group_name = entry.attrib.get("name")
        
        # Extract devices within the group
        devices = []
        for device in entry.findall(".//devices/entry"):
            device_serial = device.attrib.get("name")
            vsys_list = [v.attrib.get("name") for v in device.findall(".//vsys/entry")]
            devices.append({
                "serial": device_serial,
                "vsys": vsys_list if vsys_list else ["vsys1"],
            })

        device_groups.append({
            "name": group_name,
            "devices": devices,
        })

    return device_groups


def get_device_group_hierarchy(hostname: str, api_key: str) -> list[dict]:
    """Fetch device group parent-child hierarchy from Panorama."""
    url = f"https://{hostname}/api/"
    params = {
        "type": "config",
        "action": "get",
        "xpath": "/config/readonly/devices/entry[@name='localhost.localdomain']/device-group",
        "key": api_key,
    }
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()

    root = ET.fromstring(response.text)
    hierarchy = []

    for entry in root.findall(".//device-group/entry"):
        group_name = entry.attrib.get("name")
        parent_dg = entry.find("parent-dg")
        hierarchy.append({
            "name": group_name,
            "parent": parent_dg.text if parent_dg is not None else None,
        })

    return hierarchy


def display_results(device_groups: list[dict], hierarchy: list[dict]) -> None:
    """Display results in a readable format."""
    print("\n" + "=" * 60)
    print(f"{'PANORAMA DEVICE GROUPS':^60}")
    print("=" * 60)
    print(f"\nTotal Device Groups Found: {len(device_groups)}\n")

    # Build a hierarchy map for quick lookup
    hierarchy_map = {h["name"]: h["parent"] for h in hierarchy}

    for group in device_groups:
        parent = hierarchy_map.get(group["name"], "None (Top-level)")
        print(f"  Device Group : {group['name']}")
        print(f"  Parent Group : {parent or 'None (Top-level)'}")
        print(f"  Device Count : {len(group['devices'])}")
        if group["devices"]:
            print("  Devices:")
            for device in group["devices"]:
                print(f"    - Serial: {device['serial']}  |  Vsys: {', '.join(device['vsys'])}")
        print("-" * 60)


def export_to_json(device_groups: list[dict], hierarchy: list[dict], output_file: str = "device_groups.json") -> None:
    """Export results to a JSON file."""
    hierarchy_map = {h["name"]: h["parent"] for h in hierarchy}
    
    export_data = []
    for group in device_groups:
        export_data.append({
            "name": group["name"],
            "parent": hierarchy_map.get(group["name"]),
            "device_count": len(group["devices"]),
            "devices": group["devices"],
        })

    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"\n✅ Results exported to: {output_file}")


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ── Configuration ──────────────────────────────────────────────────────
    PANORAMA_HOST = "your-panorama-hostname-or-ip"
    USERNAME      = "your-username"
    PASSWORD      = "your-password"
    EXPORT_JSON   = True   # Set to False to skip JSON export
    # ───────────────────────────────────────────────────────────────────────

    print(f"Connecting to Panorama: {PANORAMA_HOST}")

    api_key = get_panorama_api_key(PANORAMA_HOST, USERNAME, PASSWORD)
    print("✅ Authentication successful.")

    device_groups = get_device_groups(PANORAMA_HOST, api_key)
    hierarchy     = get_device_group_hierarchy(PANORAMA_HOST, api_key)

    display_results(device_groups, hierarchy)

    if EXPORT_JSON:
        export_to_json(device_groups, hierarchy, "device_groups.json")
