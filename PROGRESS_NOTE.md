# Progress Note

**Date:** 2026-01-22

**Summary:**
- Received a multi-part request suite: implement SNMP/network discovery, streaming results, UI updates, MAC/Network scanner, history visualization, and eventually evolve the RMM platform into a multi-tenant architecture with separated storage/auth layers.
- Observed existing build issues (SNMP/SharpSnmp warnings/errors, server-side JS duplicate identifiers) and numerous UI/UX requests for controls, settings, etc.
- Newer focus is on storage/auth refactoring to prepare for multi-tenancy.

**Open Questions/Blocks:**
- Clarification needed on preferred storage/auth design (e.g., separate DB per tenant vs shared schema).
- UI placement and flows for multi-tenant selection, SNMP/network scanner integration, and history dashboards.
- Need to confirm expected data model for incremental streaming of SNMP v3 discovery.

**Next Steps:**
1. Investigate current storage and authentication layers to determine chokepoints for tenancy separation.
2. Sketch a tenancy-aware architecture (tenant metadata, global admin scope, isolated agent/store relationships).
3. Update server/index files to support configurable base URLs or tenant contexts, ensuring new network scanner logging respects tenancy.
