# 08 - CIP Class 0x01: Identity Object Discovery

## Overview

The **Identity Object** (Class `0x01`) is one of the fundamental standard objects defined by the Common Industrial Protocol (CIP). Every ODVA-compliant EtherNet/IP device implements this object to expose basic identification information such as the manufacturer, device type, firmware revision, serial number, and product name.

Clients typically retrieve these values using the **Get Attribute Single** (`0x0E`) service by addressing specific attributes within Instance `0x01`.

---

## Identity Object Attributes

The Identity Object defines a standard set of attributes that uniquely identify a device and describe its capabilities.

| Attribute | Field         | Data Type      | Description                               |
| :-------- | :------------ | :------------- | :---------------------------------------- |
| `0x01`    | Vendor ID     | `UINT`         | Manufacturer identifier assigned by ODVA  |
| `0x02`    | Device Type   | `UINT`         | General device classification             |
| `0x03`    | Product Code  | `UINT`         | Vendor-specific hardware model identifier |
| `0x04`    | Revision      | `STRUCT`       | Major and minor firmware revision         |
| `0x05`    | Status        | `WORD`         | Operational status and device state flags |
| `0x06`    | Serial Number | `UDINT`        | Unique 32-bit device serial number        |
| `0x07`    | Product Name  | `SHORT_STRING` | Human-readable device name                |

These attributes provide a standardized mechanism for identifying EtherNet/IP devices regardless of manufacturer.

---

## Response Structure

A successful `Get Attribute Single` request returns a standard CIP service reply followed by the requested attribute encoded in its native format.

The following example illustrates how multiple Identity Object attributes may appear within a decoded response.

```text id="81ynvh"
+-----------------------------------------------------------+
| CIP Application Payload                                   |
+-----------------------------------------------------------+
| 8E 00 00 00                                               |
|   -> Service Reply : 0x8E                                |
|   -> General Status: 0x00 (Success)                       |
+-----------------------------------------------------------+
| Attribute Data                                             |
|   -> 01 00 : Vendor ID                                   |
|   -> 0E 00 : Device Type                                 |
|   -> 39 05 : Product Code                                |
|   -> 02 01 : Revision (Major 2, Minor 1)                 |
|   -> 0A 43 50 50 50 4F ... : Product Name                |
+-----------------------------------------------------------+
```

The returned values are encoded according to each attribute's defined data type. Fixed-size attributes such as `Vendor ID` and `Device Type` are returned as binary integers, while the `Product Name` is encoded as a length-prefixed `SHORT_STRING`.

---

## Security Characteristics

* The Identity Object exposes standardized device identification information through well-defined CIP attributes.
* Manufacturer identifiers, firmware revisions, product codes, and serial numbers can assist with device inventory, asset identification, and vulnerability correlation.
* Identity Object queries are commonly performed during passive discovery and active asset enumeration.
* Because these attributes are standardized across ODVA-compliant devices, they provide a consistent mechanism for identifying EtherNet/IP assets from different vendors.

---

## Key Takeaways

* The Identity Object (Class `0x01`) provides standardized identification information for EtherNet/IP devices.
* Device information is retrieved by reading individual attributes within Instance `0x01`.
* Standard attributes include the Vendor ID, Device Type, Product Code, Revision, Status, Serial Number, and Product Name.
* Attribute values are returned using their native CIP data types rather than a generic response format.
* The Identity Object plays a central role in device discovery, inventory management, and protocol reconnaissance.
