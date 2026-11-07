# Approved sanctions projection

`internal/disclosuresanctions` matches the sanctions rows in one immutable
approved bundle against a supplied address set. It uses the existing compliance
catalog and makes no database or provider requests.

`New` captures the bundle manifest digest, compliance catalog digest, configured
organizations and validated catalog rows. `Match` accepts an exact configured
organization and at most 4,096 unique binary addresses in increasing order.
It returns the applicable global and organization rows in catalog ID order,
preserving their actual IDs and reasons. Two applicable rows for the same address
remain distinct. Results are detached, and concurrent calls share no mutable data.

This operation does not establish that the supplied addresses are complete or
that anyone may disclose them. An empty input or match set carries no “clear” or
“not applicable” verdict. A missing compliance catalog is unsupported; an approved
empty catalog is a valid empty policy population. This is a check against the
approved list, not every external sanctions list.

A disclosure source must separately qualify the requested population, provenance,
current permission and source cut before building a report. Protected output uses
the disclosure validator and renderer, which exposes reasons only at `Full`.
The projection itself provides no endpoint, disclosure authority, source descriptor
or report-completeness capability.
