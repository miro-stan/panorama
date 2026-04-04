import requests
import xml.etree.ElementTree as ET
import urllib3
import json
import copy
from dataclasses import dataclass, field, asdict
from typing import Optional, Union

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class Device:
    serial: str
    vsys: list[str] = field(default_factory=list)
    name: str = ""
    mgmt_ip: str = ""

@dataclass
class AddressObject:
    name: str
    type: str
    value: str
    description: str = ""
    tags: list[str] = field(default_factory=list)

@dataclass
class AddressGroup:
    name: str
    type: str
    members: list[str] = field(default_factory=list)
    filter: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

@dataclass
class ServiceObject:
    name: str
    protocol: str
    src_port: str = ""
    dst_port: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

@dataclass
class ServiceGroup:
    name: str
    members: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

@dataclass
class Tag:
    name: str
    color: str = ""
    comments: str = ""

@dataclass
class SecurityRule:
    name: str
    rule_name: str
    device_group: str
    rule_type: str = "universal"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_zones: list[str] = field(default_factory=list)
    destination_zones: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    action: str = ""
    profile_setting: dict = field(default_factory=dict)
    log_setting: str = ""
    log_start: bool = False
    log_end: bool = True
    disabled: bool = False

@dataclass
class NatRule:
    name: str
    rule_name: str
    device_group: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_zones: list[str] = field(default_factory=list)
    destination_zones: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    nat_type: str = "ipv4"
    source_translation: dict[str, Union[str, list[str]]] = field(default_factory=dict)
    destination_translation: dict[str, str] = field(default_factory=dict)
    disabled: bool = False

@dataclass
class DeviceGroupData:
    name: str
    parent: Optional[str] = None
    devices: list[Device] = field(default_factory=list)
    address_objects: list[AddressObject] = field(default_factory=list)
    address_groups: list[AddressGroup] = field(default_factory=list)
    service_objects: list[ServiceObject] = field(default_factory=list)
    service_groups: list[ServiceGroup] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    pre_security_rules: list[SecurityRule] = field(default_factory=list)
    post_security_rules: list[SecurityRule] = field(default_factory=list)
    pre_nat_rules: list[NatRule] = field(default_factory=list)
    post_nat_rules: list[NatRule] = field(default_factory=list)


# ── Panorama API Client ──────────────────────────────────────────────────────

class PanoramaClient:
    BASE_XPATH    = "/config/devices/entry[@name='localhost.localdomain']"
    NO_CACHE_HEADERS = {"Cache-Control": "no-cache", "Pragma": "no-cache"}

    def __init__(self, hostname: str, api_key: str, verify_ssl: bool = False):
        self.hostname   = hostname
        self.api_key    = api_key
        self.verify_ssl = verify_ssl
        self.base_url   = f"https://{hostname}/api/"

    @classmethod
    def from_credentials(cls, hostname: str, username: str, password: str, verify_ssl: bool = False) -> "PanoramaClient":
        url  = f"https://{hostname}/api/"
        resp = requests.get(
            url,
            params ={"type": "keygen", "user": username, "password": password},
            verify =verify_ssl,
            headers=cls.NO_CACHE_HEADERS,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") != "success":
            raise Exception("Authentication failed. Check your credentials.")

        # Fix error 1 & 2: find().text is str | None — validate before use
        key_node = root.find(".//key")
        if key_node is None or key_node.text is None:
            raise Exception("API key not found in Panorama response.")
        api_key: str = key_node.text

        print("✅ Authentication successful.")
        return cls(hostname, api_key, verify_ssl)

    def _query(self, xpath: str) -> ET.Element:
        """Execute a config GET query and return the root XML element."""
        resp = requests.get(
            self.base_url,
            params  ={"type": "config", "action": "get", "xpath": xpath, "key": self.api_key},
            verify  =self.verify_ssl,
            headers =self.NO_CACHE_HEADERS,
        )
        resp.raise_for_status()
        root = copy.deepcopy(ET.fromstring(resp.text))
        if root.attrib.get("status") != "success":
            raise Exception(f"Query failed for xpath [{xpath}]: {resp.text}")
        return root

    def _op(self, cmd: str) -> ET.Element:
        """Execute an operational (op) command and return the root XML element."""
        resp = requests.get(
            self.base_url,
            params  ={"type": "op", "cmd": cmd, "key": self.api_key},
            verify  =self.verify_ssl,
            headers =self.NO_CACHE_HEADERS,
        )
        resp.raise_for_status()
        root = copy.deepcopy(ET.fromstring(resp.text))
        if root.attrib.get("status") != "success":
            raise Exception(f"Op command failed [{cmd}]: {resp.text}")
        return root

    def _dg_xpath(self, dg_name: str, sub_path: str = "") -> str:
        return f"{self.BASE_XPATH}/device-group/entry[@name='{dg_name}']{sub_path}"

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _members(element: Optional[ET.Element]) -> list[str]:
        if element is None:
            return []
        return [m.text for m in element.findall("member") if m.text]

    @staticmethod
    def _text(element: ET.Element, tag: str, default: str = "") -> str:
        node = element.find(tag)
        return node.text if node is not None and node.text else default

    @staticmethod
    def _tags(element: ET.Element) -> list[str]:
        return PanoramaClient._members(element.find("tag"))

    # ── Device Groups ────────────────────────────────────────────────────────

    def get_device_group_names(self) -> list[str]:
        root = self._query(f"{self.BASE_XPATH}/device-group")
        return [e.attrib["name"] for e in root.findall(".//device-group/entry")]

    def get_device_group_hierarchy(self) -> dict[str, Optional[str]]:
        root = self._query(f"/config/readonly{self.BASE_XPATH}/device-group")
        result = {}
        for e in root.findall(".//device-group/entry"):
            parent_node = e.find("parent-dg")
            result[e.attrib["name"]] = parent_node.text if parent_node is not None else None
        return result



    # def get_device_group_hierarchy(self) -> dict[str, Optional[str]]:
    #     root = self._query(f"/config/readonly{self.BASE_XPATH}/device-group")
    #     return {
    #         e.attrib["name"]: (e.find("parent-dg").text if e.find("parent-dg") is not None else None)
    #         for e in root.findall(".//device-group/entry")
    #     }

    # ── Devices ──────────────────────────────────────────────────────────────

    def _get_connected_device_info(self) -> dict[str, dict[str, str]]:
        """
        Fetch hostname and management IP for every device Panorama knows about.
        Returns a dict keyed by serial: {"name": ..., "mgmt_ip": ...}
        """
        device_info: dict[str, dict[str, str]] = {}
        try:
            root = self._op("<show><devices><all></all></devices></show>")
            for entry in root.findall(".//devices/entry"):
                serial  = entry.attrib.get("name", "")
                name    = self._text(entry, "hostname")
                mgmt_ip = self._text(entry, "ip-address")
                if serial:
                    device_info[serial] = {"name": name, "mgmt_ip": mgmt_ip}
        except Exception as ex:
            print(f"    ⚠️  Could not fetch device info (name/IP): {ex}")
        return device_info

    def get_devices_in_group(self, dg_name: str, device_info: dict[str, dict[str, str]]) -> list[Device]:
        root    = self._query(self._dg_xpath(dg_name, "/devices"))
        devices = []
        for entry in root.findall(".//devices/entry"):
            serial = entry.attrib["name"]
            vsys   = [v.attrib["name"] for v in entry.findall(".//vsys/entry")]
            info   = device_info.get(serial, {})
            devices.append(Device(
                serial  = serial,
                vsys    = vsys or ["vsys1"],
                name    = info.get("name", ""),
                mgmt_ip = info.get("mgmt_ip", ""),
            ))
        return devices

    # ── Object Parsers ───────────────────────────────────────────────────────

    def get_address_objects(self, dg_name: str) -> list[AddressObject]:
        root    = self._query(self._dg_xpath(dg_name, "/address"))
        objects = []
        for e in root.findall(".//address/entry"):
            e         = copy.deepcopy(e)
            addr_type = "unknown"
            value     = ""
            for t in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
                node = e.find(t)
                if node is not None:
                    addr_type = t
                    value     = node.text or ""
                    break
            objects.append(AddressObject(
                name        = e.attrib["name"],
                type        = addr_type,
                value       = value,
                description = self._text(e, "description"),
                tags        = self._tags(e),
            ))
        return objects

    def get_address_groups(self, dg_name: str) -> list[AddressGroup]:
        root   = self._query(self._dg_xpath(dg_name, "/address-group"))
        groups = []
        for e in root.findall(".//address-group/entry"):
            e            = copy.deepcopy(e)
            static_node  = e.find("static")
            dynamic_node = e.find("dynamic/filter")

            # Fix error 3: dynamic_node.text is str | None — default to ""
            dynamic_filter = dynamic_node.text if dynamic_node is not None and dynamic_node.text is not None else ""

            groups.append(AddressGroup(
                name        = e.attrib["name"],
                type        = "static" if static_node is not None else "dynamic",
                members     = self._members(static_node),
                filter      = dynamic_filter,
                description = self._text(e, "description"),
                tags        = self._tags(e),
            ))
        return groups

    def get_service_objects(self, dg_name: str) -> list[ServiceObject]:
        root     = self._query(self._dg_xpath(dg_name, "/service"))
        services = []
        for e in root.findall(".//service/entry"):
            e                        = copy.deepcopy(e)
            proto, src_port, dst_port = "unknown", "", ""
            for p in ("tcp", "udp", "sctp"):
                proto_node = e.find(f"protocol/{p}")
                if proto_node is not None:
                    proto    = p
                    src_port = self._text(proto_node, "source-port")
                    dst_port = self._text(proto_node, "port")
                    break
            services.append(ServiceObject(
                name        = e.attrib["name"],
                protocol    = proto,
                src_port    = src_port,
                dst_port    = dst_port,
                description = self._text(e, "description"),
                tags        = self._tags(e),
            ))
        return services

    def get_service_groups(self, dg_name: str) -> list[ServiceGroup]:
        root = self._query(self._dg_xpath(dg_name, "/service-group"))
        return [
            ServiceGroup(
                name    = e.attrib["name"],
                members = self._members(e.find("members")),
                tags    = self._tags(e),
            )
            for e in root.findall(".//service-group/entry")
        ]

    def get_tags(self, dg_name: str) -> list[Tag]:
        root = self._query(self._dg_xpath(dg_name, "/tag"))
        return [
            Tag(
                name     = e.attrib["name"],
                color    = self._text(e, "color"),
                comments = self._text(e, "comments"),
            )
            for e in root.findall(".//tag/entry")
        ]

    # ── Policy Parsers ───────────────────────────────────────────────────────

    def _parse_security_rules(self, root: ET.Element, dg_name: str) -> list[SecurityRule]:
        rules = []
        for e in root.findall(".//rules/entry"):
            e = copy.deepcopy(e)

            profile_setting: dict[str, str] = {}
            ps = e.find("profile-setting")
            if ps is not None:
                group_node = ps.find("group/member")
                if group_node is not None:
                    profile_setting = {"type": "group", "name": group_node.text or ""}
                else:
                    profile_setting = {
                        "type":    "profiles",
                        "av":      self._text(ps, "profiles/virus/member"),
                        "vuln":    self._text(ps, "profiles/vulnerability/member"),
                        "url":     self._text(ps, "profiles/url-filtering/member"),
                        "spyware": self._text(ps, "profiles/spyware/member"),
                    }

            log_start     = self._text(e, "log-start", default="no")  == "yes"
            log_end       = self._text(e, "log-end",   default="yes") == "yes"
            original_name = e.attrib["name"]

            rules.append(SecurityRule(
                name                  = f"{dg_name}::{original_name}",
                rule_name             = original_name,
                device_group          = dg_name,
                rule_type             = self._text(e, "rule-type", "universal"),
                description           = self._text(e, "description"),
                tags                  = self._tags(e),
                source_zones          = self._members(e.find("from")),
                destination_zones     = self._members(e.find("to")),
                source_addresses      = self._members(e.find("source")),
                destination_addresses = self._members(e.find("destination")),
                applications          = self._members(e.find("application")),
                services              = self._members(e.find("service")),
                action                = self._text(e, "action"),
                profile_setting       = profile_setting,
                log_setting           = self._text(e, "log-setting"),
                log_start             = log_start,
                log_end               = log_end,
                disabled              = self._text(e, "disabled") == "yes",
            ))
        return rules

    def _parse_nat_rules(self, root: ET.Element, dg_name: str) -> list[NatRule]:
        rules = []
        for e in root.findall(".//rules/entry"):
            e = copy.deepcopy(e)

            src_xlat: dict[str, Union[str, list[str]]] = {}
            dst_xlat: dict[str, str]                   = {}

            src_node = e.find("source-translation")
            if src_node is not None:
                for stype in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"):
                    st = src_node.find(stype)
                    if st is not None:
                        src_xlat = {"type": stype}

                        addr = st.find("translated-address")
                        if addr is not None:
                            members = self._members(addr)
                            # Fix error 4: guarantee str, never None, when falling
                            # back to element text for single static IP entries
                            src_xlat["translated-address"] = members if members else (addr.text or "")

                        iface = st.find("interface-address/interface")
                        if iface is not None:
                            # Fix error 5: iface.text is str | None — default to ""
                            src_xlat["interface"] = iface.text or ""

                        break

            dst_node = e.find("destination-translation")
            if dst_node is not None:
                dst_xlat = {
                    "translated-address": self._text(dst_node, "translated-address"),
                    "translated-port":    self._text(dst_node, "translated-port"),
                }

            original_name = e.attrib["name"]

            rules.append(NatRule(
                name                    = f"{dg_name}::{original_name}",
                rule_name               = original_name,
                device_group            = dg_name,
                description             = self._text(e, "description"),
                tags                    = self._tags(e),
                source_zones            = self._members(e.find("from")),
                destination_zones       = self._members(e.find("to")),
                source_addresses        = self._members(e.find("source")),
                destination_addresses   = self._members(e.find("destination")),
                services                = self._members(e.find("service")) or [self._text(e, "service")],
                nat_type                = self._text(e, "nat-type", "ipv4"),
                source_translation      = src_xlat,
                destination_translation = dst_xlat,
                disabled                = self._text(e, "disabled") == "yes",
            ))
        return rules

    def get_security_rules(self, dg_name: str, position: str = "pre") -> list[SecurityRule]:
        root = self._query(self._dg_xpath(dg_name, f"/{position}-rulebase/security"))
        return self._parse_security_rules(root, dg_name)

    def get_nat_rules(self, dg_name: str, position: str = "pre") -> list[NatRule]:
        root = self._query(self._dg_xpath(dg_name, f"/{position}-rulebase/nat"))
        return self._parse_nat_rules(root, dg_name)

    # ── Full Device Group Extraction ─────────────────────────────────────────

    def fetch_device_group(self, dg_name: str, parent: Optional[str], device_info: dict[str, dict[str, str]]) -> DeviceGroupData:
        dg = DeviceGroupData(name=dg_name, parent=parent)

        steps = [
            ("devices",             lambda n=dg_name: self.get_devices_in_group(n, device_info), "devices"),
            ("address objects",     lambda n=dg_name: self.get_address_objects(n),               "address_objects"),
            ("address groups",      lambda n=dg_name: self.get_address_groups(n),                "address_groups"),
            ("service objects",     lambda n=dg_name: self.get_service_objects(n),               "service_objects"),
            ("service groups",      lambda n=dg_name: self.get_service_groups(n),                "service_groups"),
            ("tags",                lambda n=dg_name: self.get_tags(n),                          "tags"),
            ("pre-security rules",  lambda n=dg_name: self.get_security_rules(n, "pre"),         "pre_security_rules"),
            ("post-security rules", lambda n=dg_name: self.get_security_rules(n, "post"),        "post_security_rules"),
            ("pre-NAT rules",       lambda n=dg_name: self.get_nat_rules(n, "pre"),              "pre_nat_rules"),
            ("post-NAT rules",      lambda n=dg_name: self.get_nat_rules(n, "post"),             "post_nat_rules"),
        ]
        for label, fn, attr in steps:
            try:
                setattr(dg, attr, fn())
            except Exception as ex:
                print(f"    ⚠️  Could not fetch {label}: {ex}")
        return dg

    def fetch_all_device_groups(self) -> list[DeviceGroupData]:
        names       = self.get_device_group_names()
        hierarchy   = self.get_device_group_hierarchy()
        device_info = self._get_connected_device_info()

        print(f"\nFound {len(names)} device group(s). Starting extraction...\n")
        result = []
        for i, name in enumerate(names, 1):
            print(f"  [{i}/{len(names)}] Extracting: {name}")
            result.append(self.fetch_device_group(name, hierarchy.get(name), device_info))
        return result


# ── Output Helpers ───────────────────────────────────────────────────────────

def print_summary(device_groups: list[DeviceGroupData]) -> None:
    print("\n" + "=" * 70)
    print(f"{'PANORAMA EXTRACTION SUMMARY':^70}")
    print("=" * 70)
    for dg in device_groups:
        print(f"\n  📁 Device Group : {dg.name}")
        print(f"     Parent        : {dg.parent or 'None (top-level)'}")
        print(f"     Devices       : {len(dg.devices)}")
        for d in dg.devices:
            label = f"{d.name} ({d.serial})" if d.name else d.serial
            print(f"       • {label:<35} {d.mgmt_ip or 'IP unknown'}")
        print(f"     ── Objects ──────────────────────────")
        print(f"       Address Objects  : {len(dg.address_objects)}")
        print(f"       Address Groups   : {len(dg.address_groups)}")
        print(f"       Service Objects  : {len(dg.service_objects)}")
        print(f"       Service Groups   : {len(dg.service_groups)}")
        print(f"       Tags             : {len(dg.tags)}")
        print(f"     ── Policies ─────────────────────────")
        for label, rules in [
            ("Pre-Security",  dg.pre_security_rules),
            ("Post-Security", dg.post_security_rules),
        ]:
            enabled  = [r for r in rules if not r.disabled]
            disabled = [r for r in rules if r.disabled]
            log_both = [r for r in rules if r.log_start and r.log_end]
            log_none = [r for r in rules if not r.log_start and not r.log_end]
            print(f"       {label:<16}: {len(rules)} rules  "
                  f"({len(enabled)} enabled, {len(disabled)} disabled)  "
                  f"log-start+end: {len(log_both)}  no logging: {len(log_none)}")
        print(f"       Pre-NAT          : {len(dg.pre_nat_rules)}")
        print(f"       Post-NAT         : {len(dg.post_nat_rules)}")
    print("\n" + "=" * 70)


def export_to_json(device_groups: list[DeviceGroupData], output_file: str = "panorama_full_export.json") -> None:
    with open(output_file, "w") as f:
        json.dump([asdict(copy.deepcopy(dg)) for dg in device_groups], f, indent=2)
    print(f"\n✅ Full export saved to: {output_file}")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    PANORAMA_HOST = "your-panorama-hostname-or-ip"
    USERNAME      = "your-username"
    PASSWORD      = "your-password"
    OUTPUT_FILE   = "panorama_full_export.json"

    print(f"Connecting to Panorama: {PANORAMA_HOST}")
    client = PanoramaClient.from_credentials(PANORAMA_HOST, USERNAME, PASSWORD)

    device_groups = client.fetch_all_device_groups()

    print_summary(device_groups)
    export_to_json(device_groups, OUTPUT_FILE)
