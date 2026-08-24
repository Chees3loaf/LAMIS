# ATLAS NetBox Integration

## Scope

NetBox is an additional ATLAS inventory destination. The existing Excel device
report remains unchanged and continues to be produced even if NetBox export or
synchronization fails.

The initial target is NetBox Community 4.6.5. Only NetBox core DCIM/IPAM models
are used so the design is portable to NetBox Enterprise.

## Object model

| ATLAS record | NetBox model | Stable identity |
| --- | --- | --- |
| Managed chassis | `dcim.device` | Device name |
| Management address | `ipam.ipaddress` | Address plus VRF |
| Physical card position | `dcim.modulebay` | Device/module plus bay name |
| Fan, control card, or MDA | `dcim.module` | Occupied module bay |
| Optic position | `dcim.modulebay` | Parent module plus port position |
| Installed optic | `dcim.module` | Occupied optic bay |
| Chassis hardware definition | `dcim.devicetype` | Manufacturer plus model |
| Replaceable hardware definition | `dcim.moduletype` | Manufacturer plus model |

Deprecated `dcim.inventoryitem` objects are deliberately not used.

### Example hierarchy

```text
RDMD001_7705 (Device: 7705 SAR-8 v2)
|-- Chassis Fan (Module: 3HE06792EA)
|-- Slot A (Module: 3HE02774AB)
|-- Slot B (Module: 3HE02774AB)
|-- MDA 1 (Module: 3HE07943AA)
|   |-- 1/1/5 (Module: 3HE04823AA)
|   `-- 1/1/6 (Module: 3HE04823AA)
|-- MDA 2 (Module: 3HE07943AA)
|   |-- 1/2/5 (Module: 3HE04823AA)
|   `-- 1/2/6 (Module: 3HE04823AA)
|-- MDA 3 (Module: 3HE03126AA)
|-- MDA 4 (Module: 3HE12504AA)
|-- MDA 5 (Module: 3HE02781AA)
`-- MDA 6 (Module: 3HE03391AC)
```

## Required organizational objects

These objects must exist before ATLAS can create devices:

1. Manufacturer: `Nokia`
2. Device role: configurable by the deployment (for example, `Router`)
3. Site: configurable by the deployment
4. Device type for each discovered chassis type
5. Module type for each discovered replaceable part

ATLAS must not guess a production site or device role. They are deployment
settings and must be selected during NetBox setup.

## Module type conventions

- Manufacturer is the normalized vendor, initially `Nokia`.
- Model is the ATLAS part type when present; otherwise the part number.
- Part number is the normalized manufacturer part number.
- A module type is shared by every installed instance of the same hardware.
- Serial number and asset tag belong to the installed module, not its type.
- Module bays use the ATLAS slot/port label verbatim so repeated scans reconcile
  the same physical position.

## ATLAS custom fields

The following custom fields provide provenance without overloading NetBox's
native fields. Their object type assignments are defined in
`data/netbox/object_blueprint.json`.

| Field | Type | Purpose |
| --- | --- | --- |
| `atlas_managed` | Boolean | Object is maintained by ATLAS |
| `atlas_source` | Text | Management address used for collection |
| `atlas_last_seen` | Date/time | Time of the latest successful observation |
| `atlas_part_type` | Text | Original ATLAS part classification |
| `atlas_description` | Long text | Description resolved by the ATLAS parts DB |

## Reconciliation policy

- Devices are matched by name. The management IP is a secondary check, not the
  primary identity.
- Installed hardware is matched by its occupied bay within the device or parent
  module.
- Module types are matched by manufacturer and model, with part number checked
  for conflicts.
- A successful scan creates missing objects and updates mutable inventory data.
- A missing component is never deleted automatically.
- API synchronization is idempotent: repeating the same observation must not
  create duplicates.
- NetBox failures are logged separately and never invalidate the Excel report.

## Backend processing boundary

```text
device collection
       |
       v
normalized ATLAS inventory
       |-------------------------------|
       v                               v
existing Excel workbook          NetBox backend
(unchanged)                       |-- CSV package
                                  `-- REST API sync
```

The normalized inventory boundary prevents the CSV exporter and API client from
depending on workbook cells or formatting.

## Creation order

The API bootstrap/synchronizer creates or resolves objects in this order:

1. Manufacturer
2. Custom fields
3. Device type and its chassis module-bay templates
4. Module types and their nested optic-bay templates
5. Device
6. Chassis module bays (normally instantiated from the device type)
7. Chassis modules
8. Nested optic bays (normally instantiated from the module type)
9. Optic modules
10. Management IP and primary-IP assignment

CSV output follows the same dependency order. Device types and module types are
API/bootstrap prerequisites rather than assumptions hidden inside a CSV file.

