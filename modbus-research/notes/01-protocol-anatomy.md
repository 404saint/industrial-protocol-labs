
# Protocol Anatomy

## Objective

Understand the structure of Modbus/TCP before implementing custom clients and conducting protocol research.

## What is Modbus?

Modbus is an industrial communication protocol originally developed for programmable logic controllers (PLCs).

The protocol allows clients to:

-   **Read process data**
    
-   **Write process data**
    
-   **Read discrete states**
    
-   **Modify discrete states**
    

Modern deployments commonly use Modbus/TCP over **TCP port 502**.

## Architecture

Modbus/TCP follows a client-server model.

Plaintext

```
+-------------+         TCP/502         +-------------+
| Modbus      | ----------------------> | PLC / Server|
| Client      |                         | OpenPLC     |
+-------------+                         +-------------+

```

-   A client initiates requests.
    
-   The PLC responds with data or an exception.
    

### Protocol Stack

-   **Application** $\rightarrow$ Modbus
    
-   **Transport** $\rightarrow$ TCP
    
-   **Network** $\rightarrow$ IP
    
-   **Link** $\rightarrow$ Ethernet
    

> 💡 **Note:** Unlike Modbus RTU, Modbus/TCP does not use serial framing or CRC fields. TCP provides the necessary transport reliability.

## MBAP Header

Every Modbus/TCP packet begins with a **7-byte MBAP header**.

**Example Packet:** `00 01 00 00 00 06 01 03 00 00 00 01`

### Breakdown:

-   `00 01` = Transaction ID
    
-   `00 00` = Protocol ID
    
-   `00 06` = Length
    
-   `01` = Unit ID
    

The remaining bytes form the **Protocol Data Unit (PDU)**.

## Protocol Data Unit (PDU)

The PDU contains the **Function Code** and **Data**.

### Example FC03 Request:

`03 00 00 00 01`

-   `03` = Read Holding Registers
    
-   `00 00` = Start Address
    
-   `00 01` = Quantity
    

## Request / Response Model

-   **Request:** `00 01 00 00 00 06 01 03 00 00 00 01`
    
-   **Response:** `00 01 00 00 00 05 01 03 02 00 00`
    

### Response Breakdown:

-   `03` = Function Code
    
-   `02` = Byte Count
    
-   `00 00` = Register Value
    

## Addressing Model

Modbus exposes several logical data spaces.

**Type**

**Function**

**Coils**

Discrete outputs (Read/Write)

**Discrete Inputs**

Read-only bits

**Holding Registers**

Read/write 16-bit values

**Input Registers**

Read-only 16-bit values

## Function Codes Observed

During testing, OpenPLC supported the following function codes:

-   **FC01:** Read Coils
    
-   **FC02:** Read Discrete Inputs
    
-   **FC03:** Read Holding Registers
    
-   **FC04:** Read Input Registers
    
-   **FC05:** Write Single Coil
    
-   **FC06:** Write Single Register
    
-   **FC15:** Write Multiple Coils
    
-   **FC16:** Write Multiple Registers
    

> ⚠️ Unsupported function codes returned Modbus exception responses.

## Exception Handling

Modbus exceptions are indicated by **setting bit 7** of the function code (adding `0x80` to the hex value).

-   **Request:** FC43 (`0x2B`)
    
-   **Response:** `AB 01`
    

### Breakdown:

-   `AB` = `2B` + `80h`
    
-   `01` = Illegal Function
    

**Observation:** OpenPLC implemented standards-compliant Modbus exception handling.

## Lab Observations

### Service Identification

Before the PLC program was running:

Plaintext

```
502/tcp open tcpwrapped

```

After runtime initialization:

Plaintext

```
502/tcp open modbus Modbus TCP

```

**Observation:** Application state directly influenced service fingerprinting results.

### Register Addressing

Testing revealed addressing inconsistencies between different tools. For example:

-   Address 0
    
-   Address 1
    
-   Register 40001
    

These may all refer to the _same_ underlying register depending on the implementation.

**Observation:** Modbus does not define a universal, human-readable register notation.

### Initial FC03 Validation

-   **Custom client request:** `000100000006010300000001`
    
-   **Response:** `0001000000050103020000`
    

**Finding:** A manually crafted Modbus/TCP packet successfully retrieved data from OpenPLC. This validated our MBAP construction, FC03 implementation, and TCP transport behavior.

## Security Characteristics

The protocol itself inherently provides:

-   **No** authentication
    
-   **No** authorization
    
-   **No** encryption
    
-   **No** integrity protection
    

Any host capable of reaching `TCP/502` can attempt read or write operations. Security depends primarily on:

-   Network segmentation
    
-   Access control lists (ACLs)
    
-   Continuous monitoring
    
-   Industrial firewalling
    

## Key Takeaways

-   Modbus/TCP uses a simple request/response model.
    
-   Every packet contains an MBAP header and a PDU.
    
-   Function codes determine the operation performed.
    
-   Exceptions are encoded by setting bit 7 of the function code.
    
-   OpenPLC implemented standards-compliant Modbus behavior.
    
-   The protocol has no built-in security mechanisms; network access effectively determines trust.
    

_This chapter becomes the foundation that all the later investigations (FC03, FC06, FC16, fingerprinting) build upon._
