# Object Model & Property Engine Analysis

## Executive Summary

This phase examined how a BACnet/IP implementation exposes and manages its internal object database through standard application services. The objective was to characterize the behavior of the server's object model, evaluate property retrieval mechanisms, observe object lifecycle operations, and assess protocol robustness when presented with atypical requests.

Five experiments were conducted against a laboratory BACnet/IP server implementing **Device Instance 1234**. The assessment demonstrated that the server exposed its complete object inventory through the `Object_List` property, successfully processed aggregated property requests using `ReadPropertyMultiple`, accepted a `CreateObject` request with a `ComplexACK` response, and handled invalid property identifiers and protected object deletion requests through standards-compliant `Error-PDU` responses without destabilizing the service.

---

# 1. Research Environment

| Component            | Description                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------- |
| **Target**           | BACnet/IP `SimpleServer`                                                                    |
| **Device Instance**  | `1234`                                                                                      |
| **Protocol**         | BACnet/IP (ANSI/ASHRAE Standard 135)                                                        |
| **Research Harness** | `object-model-and-properties.py`                                                            |
| **Assessment Scope** | Object enumeration, property services, object lifecycle operations, and protocol robustness |

---

# 2. Research Objectives

This phase investigated five aspects of the BACnet object database:

* Enumerate the exposed object model using `Object_List`.
* Evaluate aggregated property retrieval through `ReadPropertyMultiple`.
* Observe the server's handling of runtime object creation requests.
* Assess robustness when processing invalid property identifiers.
* Determine how protected object deletion requests are handled.

---

# 3. Experimental Analysis

## 3.1 Object Enumeration via `Object_List`

The first experiment evaluated whether the server exposed its internal object database through the standard `ReadProperty` service.

### Test Parameters

| Parameter         | Value                 |
| ----------------- | --------------------- |
| Service           | `ReadProperty (0x0C)` |
| Object            | `Device : 1234`       |
| Property          | `Object_List (76)`    |
| Expected Response | `ComplexACK`          |

### Observations

The request completed successfully and returned the controller's object inventory. The harness identified **76 BACnet objects**, including standard object types such as:

* Device
* Analog Input
* Analog Output
* Analog Value
* Binary Input
* Binary Output
* Binary Value

The response also contained several object types reported as **Vendor/Unknown**, including Type **18**, Type **31**, and Type **56**. The harness displayed the first ten entries before truncating the remaining objects for readability.

### Discussion

The `Object_List` property provides a standardized mechanism for discovering the contents of a BACnet device. In this implementation, the property was accessible without any prior authentication or session establishment, allowing complete enumeration of the exposed object database.

While this behavior is consistent with standard BACnet operation, unrestricted access to the object inventory significantly reduces the effort required to understand the logical structure of the controller before interacting with individual objects.

---

## 3.2 Multi-Property Retrieval

The second experiment evaluated the server's implementation of the `ReadPropertyMultiple` service.

### Test Parameters

| Parameter            | Value                                                            |
| -------------------- | ---------------------------------------------------------------- |
| Service              | `ReadPropertyMultiple (0x0E)`                                    |
| Object               | `Device : 1234`                                                  |
| Requested Properties | `Object_Name (77)`, `Model_Name (70)`, `Vendor_Identifier (149)` |

### Observations

The server returned a `ComplexACK` containing responses for all requested properties within a single transaction.

Returned values included:

| Property            | Response            |
| ------------------- | ------------------- |
| `Object_Name`       | `SimpleServer`      |
| `Model_Name`        | `GNU`               |
| `Vendor_Identifier` | `ERROR property/32` |

The unsupported property did not terminate processing of the remaining requests.

### Discussion

The experiment demonstrates that the implementation correctly processed aggregated property requests while reporting individual property-level exceptions independently. Rather than aborting the transaction after encountering an unsupported property, the server continued processing the remaining properties and returned all available results within a single response.

---

## 3.3 Runtime Object Creation

The third experiment evaluated support for the `CreateObject` application service.

### Test Parameters

| Parameter             | Value                   |
| --------------------- | ----------------------- |
| Service               | `CreateObject (0x0A)`   |
| Requested Object Type | `Analog Value (Type 2)` |

### Observations

The server responded with a `ComplexACK`, indicating successful processing of the `CreateObject` request.

No additional verification was performed to determine whether the object persisted within the server's object database after the transaction completed.

### Discussion

The observed behavior indicates that the implementation accepted the application service request without generating an application-layer error. Because this experiment did not perform follow-up enumeration or state validation, it cannot independently confirm the lifetime or persistence of the newly requested object.

From a security perspective, implementations exposing runtime object management services may increase the available attack surface if access to these services is not appropriately restricted. The practical impact depends on vendor-specific implementation details and deployment configuration rather than the protocol service itself.

---

## 3.4 Invalid Property Identifier Handling

The fourth experiment examined the server's handling of an extended property identifier outside the range of implemented properties.

### Test Parameters

| Parameter           | Value                 |
| ------------------- | --------------------- |
| Service             | `ReadProperty (0x0C)` |
| Property Identifier | `9999`                |

### Observations

The request generated a standards-compliant `Error-PDU`.

The server reported:

* **Error Class:** `property`
* **Error Code:** `32`

The connection remained active throughout the experiment, and subsequent requests completed successfully.

### Discussion

The implementation handled the invalid property request without terminating the session or exhibiting abnormal behavior. The returned `Error-PDU` indicates that request validation occurred at the application layer after successful packet decoding, demonstrating robust exception handling for unsupported property identifiers.

---

## 3.5 Protected Object Deletion

The final experiment evaluated how the server handled deletion of its root Device object.

### Test Parameters

| Parameter     | Value                 |
| ------------- | --------------------- |
| Service       | `DeleteObject (0x14)` |
| Target Object | `Device : 1234`       |

### Observations

The request resulted in an `Error-PDU`.

The returned response reported:

* **Error Class:** `object`
* **Error Code:** `23`

The server remained operational after processing the request.

### Discussion

The implementation rejected the deletion request while maintaining protocol compliance and application stability. Although the harness identified the returned error code numerically, the experiment confirms that the server refused the requested operation rather than attempting to process deletion of the root Device object.

---

# 4. Security Characteristics

The experiments demonstrate that the BACnet object database forms a central interface for both legitimate management operations and protocol reconnaissance.

Three observations are particularly noteworthy:

* The complete object inventory was accessible through the standard `Object_List` property.
* The implementation processed multi-property requests efficiently while isolating property-specific errors.
* Object lifecycle and malformed request handling remained stable, returning standards-compliant `Error-PDU` responses rather than exhibiting parser failures or service instability.

The acceptance of the `CreateObject` request also highlights the importance of implementation-specific access controls. While object creation is a standardized BACnet service, exposing it without appropriate authorization mechanisms may expand the operational attack surface depending on the deployment environment.

---

# 5. Hardening Recommendations

Based on the observed behavior, the following defensive measures are recommended:

1. Restrict access to object discovery and property retrieval services where operationally feasible.
2. Review whether runtime object management services such as `CreateObject` are required in production deployments, and disable or restrict them when unnecessary.
3. Segment BACnet/IP networks using dedicated OT network boundaries and limit UDP port **47808** access to authorized engineering and supervisory systems.
4. Monitor for unexpected object creation activity and unusual application-service usage as part of routine network monitoring.
