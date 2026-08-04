# Final Assessment

This research series examined the operational mechanics of BACnet/IP through a controlled laboratory environment, focusing on protocol behaviour rather than product-specific exploitation. Across four experimental phases, the study explored the architecture of the BACnet object database, command arbitration through the Priority Array, network traversal mechanisms implemented by BVLL and BBMD services, and the protocol's event-driven communication model.

The investigation confirmed that standard BACnet services expose a significant amount of operational metadata through normal protocol interactions. Object enumeration, property inspection, and priority-based command processing were all observable using standard BACnet requests without requiring proprietary tooling. The experiments also demonstrated successful Change-of-Value (COV) subscriptions, runtime modification of selected object properties, and Foreign Device Registration against the laboratory implementation.

Several observations were implementation-specific rather than protocol-wide. The laboratory `SimpleServer` accepted dynamic object creation requests, exposed its complete object inventory, and exhibited an apparent discrepancy between requested priority slots and the stored `Priority_Array` entry. These behaviours should be interpreted as characteristics of the evaluated implementation rather than inherent vulnerabilities within the BACnet specification itself.

The assessment also highlighted several environmental limitations. The laboratory consisted of a single BACnet/IP device operating without routed BACnet networks, preventing validation of BBMD forwarding behaviour, router discovery across multiple BACnet networks, and MS/TP media traversal. Likewise, no BACnet Secure Connect (BACnet/SC) infrastructure was present, restricting transport analysis to conventional BACnet/IP over UDP.

Despite these constraints, the research successfully established a practical understanding of BACnet's object-oriented architecture, service model, packet structure, and command arbitration mechanisms. More importantly, it provided empirical observations of protocol behaviour captured through packet construction, response analysis, and implementation testing rather than relying solely on specification review.

---

## Research Scope

The following protocol components were successfully investigated throughout this research series:

| Phase   | Research Area                                         | Status      |
| ------- | ----------------------------------------------------- | ----------- |
| Phase 1 | Object Model & Property Engine                        | ✅ Completed |
| Phase 2 | Priority Array & Command Arbitration                  | ✅ Completed |
| Phase 3 | BVLL, BBMD & Network Traversal                        | ✅ Completed |
| Phase 4 | COV Services, Event Properties & BACnet/SC Assessment | ✅ Completed |

---

## Research Limitations

The following capabilities were outside the scope of the current laboratory:

* Multi-subnet BBMD forwarding between independent BACnet/IP networks.
* Native BACnet MS/TP routing through production field controllers.
* Vendor-specific proprietary BACnet object implementations.
* Large-scale device interoperability testing.
* BACnet Secure Connect (BACnet/SC) deployment with TLS and WebSocket infrastructure.

---

## Future Work

Future research may extend this work by evaluating BACnet implementations from multiple vendors, constructing multi-router BACnet topologies, examining MS/TP routing behaviour, and assessing BACnet Secure Connect deployments under production-like conditions. Additional investigation into vendor-specific object models, intrinsic reporting mechanisms, trend logging, scheduling services, and access control objects would further expand understanding of real-world BACnet deployments.

---

## Ethical Statement

All experiments documented in this repository were conducted within an isolated laboratory environment using intentionally deployed BACnet services for research and educational purposes. No testing was performed against production Building Automation Systems or third-party infrastructure. The techniques described are intended to improve protocol understanding, defensive analysis, and secure deployment practices within Building Automation and Operational Technology environments.

