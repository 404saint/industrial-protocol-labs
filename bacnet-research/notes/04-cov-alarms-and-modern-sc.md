# Event Mechanics, COV & BACnet Secure Connect Assessment

## Executive Summary

This phase investigated three protocol mechanisms within the laboratory BACnet/IP implementation:

* Change-of-Value (COV) subscriptions
* Runtime modification of the `Event_Enable` property
* Availability of BACnet Secure Connect (BACnet/SC)

The assessment confirmed that the target accepted a `SubscribeCOV` request and subsequently generated an asynchronous `UnconfirmedCOVNotification`. The `Event_Enable` property was successfully modified from `0x00` to `0xE0`, with the change verified through independent pre- and post-write property reads. Finally, transport probing identified no active BACnet Secure Connect listener, indicating that all protocol communication occurred over conventional BACnet/IP.

---

# 1. Research Environment

| Component            | Description                                                                      |
| -------------------- | -------------------------------------------------------------------------------- |
| **Target**           | BACnet/IP `SimpleServer`                                                         |
| **Protocol**         | BACnet/IP (ANSI/ASHRAE Standard 135)                                             |
| **Research Harness** | `cov-alarms-sc-transition.py`                                                    |
| **Assessment Scope** | SubscribeCOV, Event_Enable property manipulation, BACnet/SC transport assessment |

---

# 2. Research Objectives

This phase investigated three protocol components:

* Validate the Change-of-Value (COV) subscription workflow.
* Assess runtime modification of the `Event_Enable` property.
* Evaluate the availability of BACnet Secure Connect (BACnet/SC).

---

# 3. Experimental Analysis

## 3.1 Change-of-Value (COV) Subscription

### Protocol Background

BACnet supports an event-driven communication model through **Change-of-Value (COV)** subscriptions. Rather than continuously polling object values, clients may subscribe to supported objects and receive asynchronous notifications whenever monitored values change.

A successful COV exchange consists of two stages:

1. The client issues a `SubscribeCOV` confirmed request.
2. The server acknowledges the subscription and subsequently transmits COV notifications whenever qualifying value changes occur.

### Test Parameters

| Parameter             | Value                        |
| --------------------- | ---------------------------- |
| Service               | `SubscribeCOV`               |
| Target Object         | Analog Input Instance 1      |
| Subscription Lifetime | `300 seconds`                |
| Notification Type     | `UnconfirmedCOVNotification` |

### Observations

The target acknowledged the subscription request using a `SimpleACK`. Shortly afterward, the research harness received an asynchronous `UnconfirmedCOVNotification`, indicating that the subscription had been successfully established.

```
SimpleACK
↓

UnconfirmedCOVNotification
```

Server-side logging recorded the corresponding event activity:

```
COVtask: Sending...
COVnotification: requested
COVnotification: Sent!
```

### Discussion

The controller successfully accepted the subscription request and generated an asynchronous COV notification. These observations confirm successful operation of the Change-of-Value workflow within the laboratory implementation.

---

## 3.2 Event_Enable Property Assessment

### Protocol Background

Objects supporting intrinsic event reporting expose Property 35 (`Event_Enable`), a BitString controlling which event transitions are enabled for the object. This assessment focused on verifying whether the property could be modified and independently validated through subsequent property reads.

### Test Parameters

| Parameter           | Value               |
| ------------------- | ------------------- |
| Property            | `Event_Enable (35)` |
| Initial Value       | `0x00`              |
| Written Value       | `0xE0`              |
| Verification Method | Read → Write → Read |

### Observations

An initial `ReadProperty` request returned a BitString value of `0x00`.

```
BitString Value: 0x00
```

A subsequent `WriteProperty` operation completed successfully and returned a `SimpleACK`.

```
SimpleACK
```

A verification read confirmed that the property value had been updated.

```
BitString Value: 0xE0
```

The server processed the write operation as expected:

```
WP: Received Request!
WP: type=0 instance=1 property=35 priority=16 index=4294967295
WP: Sending Simple Ack!
```

### Discussion

The experiment demonstrates that the `Event_Enable` property accepted a modified BitString value and retained the updated state following verification. The assessment did not evaluate whether altering the property changed runtime alarm behavior under operational conditions.

---

## 3.3 BACnet Secure Connect (BACnet/SC)

### Protocol Background

BACnet Secure Connect (BACnet/SC) replaces conventional BACnet/IP UDP transport with TLS-protected WebSocket communication, providing authenticated and encrypted protocol transport between participating devices.

### Test Parameters

| Parameter    | Value                                |
| ------------ | ------------------------------------ |
| Target Port  | `47809/TCP`                          |
| Probe Method | TCP Connection + WebSocket Handshake |

### Observations

A connection attempt was made to the standard BACnet/SC service port.

The connection was refused before any WebSocket negotiation or TLS session could be established.

```
Connection Refused
```

### Discussion

No BACnet Secure Connect listener was detected during the experiment. Consequently, all observed protocol communication occurred over conventional BACnet/IP.

---

# 4. Security Characteristics

This phase examined BACnet's event services and transport mechanisms rather than application-layer object management.

Three observations were recorded during testing:

* The target accepted a `SubscribeCOV` request and generated asynchronous COV notifications.
* The `Event_Enable` property accepted runtime modification through `WriteProperty`, with the updated value verified through subsequent reads.
* No BACnet Secure Connect listener was available, leaving BACnet/IP as the active transport mechanism.

Collectively, these observations illustrate BACnet's event-driven communication model while highlighting the distinction between legacy BACnet/IP deployments and environments implementing BACnet Secure Connect.

---

# 5. Hardening Recommendations

Based on the observed behavior, the following practices are recommended:

1. Restrict Change-of-Value subscriptions to trusted supervisory systems where operationally required.
2. Monitor modifications to event-related properties, including `Event_Enable`, as part of routine controller auditing.
3. Deploy BACnet Secure Connect where supported to provide authenticated and encrypted communications.
4. Segment BACnet/IP networks from enterprise infrastructure using dedicated OT network boundaries and firewall controls.
5. Periodically review object event configuration to ensure event-processing properties align with operational requirements and organizational security policies.
