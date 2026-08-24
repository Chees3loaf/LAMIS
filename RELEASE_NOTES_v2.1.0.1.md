# ATLAS v2.1.0.1 — Release Notes

## ✨ New: Ciena RLS Route Builder — unified offline review
- **One offline RLS entry** — Route Builder now owns diagram import, ordered
  shelves, selected-shelf configuration review, MOP preview, and final bundle
  export.
- **R4.0-only software contract** — the R4.2 generator, protected-DCI payload
  schema, editor, exporter, legacy adapter, extraction tooling, and public API
  have been removed. Release is fixed to `RLS R4.0`; explicit other-release
  evidence is preserved for a clear rejection and is never converted.
- **High-reasoning, facts-only diagram extraction** — dense diagrams use an
  overview plus detail views to transcribe visible route facts and evidence.
  Vision does not invent releases, hardware variants, TIDs/IPs, or
  configuration defaults.
- **Exact selected-shelf review** — RLS R4.0 Add/Drop, ILA, and ROADM roles
  open an exact-provider editor. ATLAS may seed one compatible advisory
  candidate, but provider confirmation remains explicit; fixed
  BOM/discriminators, the editable unverified target-build/schema candidate,
  OAM, provider-cardinality line records/PFG neighbors, and route topology
  must validate before the payload can be applied. Provider-specific
  deployment-control procedures are attached in the background without a
  separate checkbox tab.
- **Providers visible at a glance** — **Ordered route shelves** now shows the
  applied, suggested, or sole route-compatible provider candidate for every
  shelf, plus explicit multiple-choice, SRA-required, stale, and incompatible
  states. A sole compatible candidate is prepopulated in the exact-review
  dropdown, while the dropdown remains catalog-driven for corrections and
  future audited providers. Catalog uniqueness never confirms the installed
  BOM or relaxes validation and deployment gates.
- **Direction maps visible at a glance** — each ordered shelf now shows whether
  the applied or sole compatible provider's physical degree 1/amplifier path 1
  faces route side A or Z. ATLAS prefers unique direct slot/port evidence and
  uses an audited provider/role fallback only when endpoint observations are
  genuinely absent. Ambiguous, conflicting, low-confidence, invalidated,
  multiple-provider, stale, unsupported-SRA, and incompatible results remain
  unresolved. The exact-review selector remains available for confirmation or
  correction, and the suggestion never creates a payload or authorizes CLI.
- **Six audited R4.0 providers** — two-degree C-band CDA RLA12 Add/Drop;
  two-degree C-band CDC RLA32/CCMD8x24 ROADM; one-degree C+L RLA12/LRU12
  terminal-core variants without SRA and with the fixed slot-6 SRA; and R2
  C+L DLE OSPF-RNE ILA variants without SRA and with the fixed slot-4 SRA.
  The C+L terminal providers deliberately exclude unproved CCMD/client,
  unrelated WSS, additional-degree, and protection scope.
- **Whole-route review retention** — applying one R4.0 review preserves other
  shelves' payloads. Final generation rechecks route identity and modeled
  optical facts.
- **Bidirectional R4.0 route fidelity** — exact-payload schema 1.5 separates
  A/Z physical side, RLA hardware degree, and A→Z/Z→A propagation. One shared
  physical span derives two endpoint-egress reviews, so opposite losses and
  link names can differ without overwriting the customer’s common
  circuit/distance evidence. The one-degree provider stores `line_2: null`;
  provider-local CLI link names are no longer populated from a repeated route
  circuit ID. A 15-span route reports 30 propagation reviews.
- **ROADM degree semantics corrected** — one represented RLA mux/demux degree
  carries both traffic directions. A blank second tab on the audited
  two-degree terminal provider is additional hardware, not the return route,
  and ATLAS never copies the visible span into it. The one-degree C+L provider
  exposes no phantom second-degree tab.
- **DLE ILA peer mapping corrected** — PFG-1-to-2 now uses its output-side
  neighbor downstream and the opposite-side neighbor upstream;
  PFG-2-to-1 swaps them, matching the R4.0 commissioning example. Reusing one
  neighbor for both physical sides is rejected.
- **Old exact payloads fail closed** — schemas 1.2 and 1.3 are retired because
  the ILA correction, variable line cardinality, and provider-local link-name
  contract materially change CLI. ATLAS opens current diagram/route facts for
  deliberate schema-1.5 review while retaining the old payload until the
  operator validates and applies its replacement. Schema 1.4 remains readable
  only with its original numeric site identity; schema 1.5 supports an
  explicit unknown (`null`) site ID without inventing zero.
- **R4.0 OSC sequencing correction** — OSC pluggables now follow the loopback
  `/32` in the same initial-OAM batch, allowing vendor-documented automatic
  unnumbered OSC creation before network-instance and OSPF binding.
- **Fail-closed path review** — pending/manual optical paths block atomic route
  CLI export, and closing an edited R4.0 review asks before discarding changes.
- **Actionable diagram accounting** — Route Builder preserves raw
  source-absence totals for audit while separately reporting unresolved
  operator inputs, controlled defaults, pending suggestions, optional
  metadata, and planned-removal exclusions. The latest supplied ELP1–SAT4
  transcription's 85 raw omissions account to zero unresolved required
  values after controlled defaults and pending suggestions; every shelf and
  optical path still requires explicit human review.
- **Diagram-to-CLI prepopulation** — exact review now carries forward every
  applicable reviewed identity, OAM, neighbor, circuit/link, fiber, loss,
  distance, and fiber-range value. Passive span facts are shown as read-only
  context, the role-only assumptions report no longer disappears because of
  editor-only fields, and privacy-safe logs count seeded/default/manual groups.
- **Direct chassis-label normalization** — an exact, directly evidenced
  `R2 600mm` or `R4 600mm` shelf-variant label can also populate chassis review
  context with preserved provenance. It may constrain the non-executable
  provider resolver, but cannot prove a BOM, create a payload, or authorize
  CLI.
- **Route-header optical band context** — a directly evidenced `C`, `L`, or
  `C+L` header value is retained and shown in exact review without being
  copied to every shelf. The route-wide value may narrow and populate the sole
  route-compatible review candidate, and it blocks conflicting-band provider
  options, Apply, saved-payload readiness, and export when no stronger direct
  shelf-band evidence documents an intentional partition. It cannot qualify a
  shelf BOM or authorize CLI by itself.
- **One fiber choice per route** — Route Builder shows the observed diagram
  label separately and applies one operator-selected, audited native R4.0
  fiber token to every active span. Uniform direct `LEAF` evidence now
  preselects the exact `LEAF` token supported by the legacy workbook and the
  R4.0 commissioning example, while retaining a warning for the conflicting
  formal enum table. It is never silently translated to `Enhanced LEAF` or
  confirmed without the operator; changing the choice invalidates dependent
  configuration reviews and the current preview.
- **Optional terminal COLAN and customer-managed NTP policy** — Add/Drop and
  ROADM may carry one complete customer-provided `colan-a` or `colan-x`
  design, or remain explicitly deferred for factory staging. Deferred
  candidates emit no COLAN commands and carry a visible warning and manifest
  state; they are not blocked solely because the on-site COLAN design is not
  yet available. ILA shelves hide and prohibit COLAN. Diagram OAM addresses
  are never reused as COLAN, and RLS exact payloads and CLI contain no NTP
  settings.
- **Automatic provider deployment controls** — the separate Confirmations tab
  has been removed. Every exact provider now carries background procedures for
  expected inventory/topology comparison, the separate customer-approved
  runtime-tuning/calibration package (including PlannerPlus when applicable),
  and exact-build validation. The C+L DLE also carries its disconnected-fiber
  and inactive Span Calibration/Passive Terminal Control staging procedure;
  the C-band CDC RLA32 carries its unused-CFIM loopback/dust-cap procedure.
  These controls are advisories, not observations or proof of physical work.
  They emit no deployment approval, keep `deployment_approved: false`, and do
  not replace successful on-box `validate`. Schema 1.5 retains the six former
  Boolean fields for round-trip compatibility, but `false` no longer blocks
  offline candidate generation and `true` never asserts physical verification.
- **Unknown staging facts remain explicit without invention** — ATLAS starts
  the editable target build/schema at the vendor-documented `4.00.00` baseline
  and marks it defaulted and unverified; it does not assert that build is
  installed. Physical rack/frame location is optional and, when blank, omits
  the complete shelf-location command. Numeric site ID is nullable and, when
  unknown, omits the complete site-identity command rather than emitting
  invented ID `0`. Terminal COLAN may remain deferred as described above.
  Missing route site/TID identity and other genuinely mandatory facts still
  block exact validation.
- **Route customer policy** — one persisted project policy supplies an
  optional node/neighbor DNS suffix, independent A- and Z-facing input/output
  patch-loss defaults, and the optional terminal-COLAN OSPF metric. The
  supplied known-good route initializes two-sided shelves at 0.5/0.5 dB on
  the A-facing pair and 0.2/0.2 dB on the Z-facing pair; route-facing terminal
  degrees initialize at 0.5/0.5 dB. Every value remains editable and policy
  changes invalidate stored route-bound payloads for fresh validation.
- **Guided shelf review** — **Confirm & Next Pending** advances through imported
  shelves one at a time. Configuration review remains gated until the route's
  shelf facts and structured RAMAN callouts are explicitly reviewed. ATLAS
  then selects the next shelf with an available exact-provider review.
- **Correct A/Z line-map seeding** — imported span facts remain keyed by route
  side. Direct port evidence has priority; if endpoint observations are
  entirely absent, a uniquely preselected provider can use its audited
  role-specific line/side convention as a non-executable fallback. Resolved
  line records immediately load adjacent neighbor, link, fiber, and loss values.
  Ambiguous/conflicting evidence never falls back, and an external endpoint
  degree remains blank instead of receiving a copied loss.
- **Header-anchored A/Z and advisory provider matching** — a directly observed
  terminal pair is checked against the first and last shelf TIDs; an exact
  reverse transcription is normalized before A/Z roles are assigned. A sole
  route-compatible catalog result may populate the review dropdown, but direct
  evidence must establish a complete provider module inventory or complete
  fixed line-output map plus chassis/degree coverage before ATLAS labels it
  hardware-qualified. Generic chassis, no-SRA/protection defaults, catalog
  uniqueness, and one terminal port cannot confirm a two-degree provider. A
  compatible fixed direction remains non-executable until the operator
  confirms and validates the exact request.
- **Safe route reordering** — changing the ordered shelves recomputes A/Z
  endpoint roles and the controlled terminal title, clears route-bound exact
  payloads, and invalidates diagram-relative port-direction suggestions whose
  original adjacency no longer proves the edited topology.
- **Audited legacy input contract** — literal column-B `<...>` inputs from
  `Ciena RLS C+L CLI Config v3.5LR.xlsx` are mapped to the integrated R4.0
  review, with provider/workflow fixed values prepopulated. Direct compatible
  diagram values take precedence; conflicting immutable hardware eliminates a
  provider candidate instead of changing its audited BOM. Spreadsheet formulas
  and generated commands remain quarantined.
- **Customer diagram in the deliverable** — the uploaded diagram is normalized
  and embedded in the MOP **Diagram** tab with internal package relationships.
  Saved projects retain hash-only provenance and provide a local-only
  **Reattach Diagram…** action before preview/export.
- **Bounded vision-edge recovery** — diagram-evidence schema 1.8 safely clips
  only right/bottom bbox overflow up to 2.5% when at least 60% of each
  dimension remains. Original and normalized geometry is retained as
  non-executable provenance; genuinely malformed critical evidence still
  blocks route replacement.
- **Bundle readiness preflight** — blocked final exports now stop before the
  folder dialog, background worker, or artifact staging and show grouped next
  actions. Accepted SRA evidence without provider coverage is identified as an
  SRA-capable-provider gap.
- **Clear fiber logging** — route-wide fiber actions avoid credential-filter
  false positives, so activity logs no longer replace harmless wording with a
  misleading `[REDACTED]` marker.
- **Unapplied-edit protection** — changing shelf selection, reordering, or
  removing a shelf can no longer silently discard visible editor changes.
- **Current preview is mandatory** — any route, shelf, OSPF, span, order, or
  configuration change invalidates the prior MOP preview. Final export requires
  a preview fingerprint that matches the unchanged current snapshot.
- **Fail-closed route bundle** — final export revalidates and regenerates the
  MOP, all eligible per-shelf candidates, reviews, validation report, project,
  and manifest together. An unsupported, incomplete, unreviewed, stale, or
  provider-gated shelf prevents the entire bundle; no partial CLI set is
  published.
- **Candidate-only CLI boundary** — every raw pre-calibration candidate uses
  `batch`, its dependency-safe configuration commands, `validate`, and `quit`.
  It deliberately contains no `commit`. The manifest remains
  `deployment_approved: false`; committing requires a separate explicitly
  approved on-box deployment workflow after successful validation on the
  matching shelf build.

## 📦 Build
- `ATLAS_Setup.exe` / `ATLAS_Setup_v2.1.0.1.exe`
- Version: `2.1.0.1` (product and file version)
- Size: `78,543,881` bytes (`74.91 MiB`)
- SHA-256:
  `1C2EF5CFEB7290FA2A57CF6BB3139D3C7694BE666EF3ED91F7B41C32D607E0B4`
- Signing status: **NotSigned** (`--no-sign` build; obtain a LightRiver
  code-signing certificate before external distribution where policy requires
  Authenticode)
