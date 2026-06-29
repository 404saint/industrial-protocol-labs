# 10 - Tag Enumeration and Attribute Boundary Discovery

## Overview

EtherNet/IP does not expose a flat memory space for discovery. Instead, visibility into controller state is distributed across CIP objects, each with its own structured attributes and instance boundaries.

Tag enumeration and boundary discovery techniques leverage this object model to infer internal structure, enumerate exposed variables, and identify valid object and attribute ranges through systematic query behavior.

---

## Symbolic Tag Space Enumeration

### Symbol Object (Class `0x6B`)

Some controllers expose symbolic tag metadata through the **Symbol Object** (`Class 0x6B`). When present, this object provides access to tag definitions stored within the controller’s runtime environment.

### Instance Discovery

A typical enumeration flow begins by querying:

* **Class**: `0x6B`
* **Instance**: `0x00`
* **Attribute**: `0x01` (Instance count, when implemented)

If supported, this returns the number of symbol entries available for iteration.

### Sequential Tag Extraction

Once the instance count is known, a client may iterate through available instances:

* `Instance 1 → Attribute 1` → Tag metadata
* `Instance 2 → Attribute 1` → Next tag entry
* …

Each valid instance typically returns a symbolic name or structured tag descriptor, depending on implementation.

It is important to note that Symbol Object support and layout can vary between vendors and firmware generations.

---

## Attribute Boundary Discovery

For standard CIP objects (such as Identity `Class 0x01` or TCP/IP Interface `Class 0xF5`), enumeration is performed by iterating through attribute indices within known instances.

This process reveals structural limits of each object by observing response behavior.

### Response-Based Boundary Detection

| Response Behavior               | General Status | Interpretation                                |
| :------------------------------ | :------------- | :-------------------------------------------- |
| Valid data returned             | `0x00`         | Attribute exists and is supported             |
| Valid object, invalid attribute | `0x14`         | Attribute not supported within valid instance |
| Invalid object path             | `0x05`         | Instance or class does not exist              |

These responses allow a scanner to infer object structure without prior knowledge of attribute counts or definitions.

---

## Observed Enumeration Model

In practice, boundary discovery follows a layered structure:

1. **Class validation** → Does the object exist?
2. **Instance probing** → Does this instance exist within the class?
3. **Attribute iteration** → Which attributes are implemented for this instance?

This hierarchical validation model is enforced by the CIP Message Router and results in predictable error signaling during enumeration attempts.

---

## Security Characteristics

* CIP object models can be enumerated without modifying controller state.
* Response codes provide structural information about class, instance, and attribute boundaries.
* Implementation differences between vendors may expose varying levels of metadata through symbolic or object-based enumeration.
* Systematic boundary probing can reveal internal structure even when tag-level access is restricted.

---

## Key Takeaways

* Tag enumeration in EtherNet/IP depends on object and instance traversal rather than flat memory scanning.
* The Symbol Object (`Class 0x6B`) may expose symbolic tag metadata when implemented.
* Attribute and instance boundaries are inferred through response codes such as `0x00`, `0x14`, and `0x05`.
* CIP enumeration follows a hierarchical model: Class → Instance → Attribute.
* Boundary discovery is driven by response behavior, not explicit metadata.
