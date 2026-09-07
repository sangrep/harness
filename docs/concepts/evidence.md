# Evidence and citations

Evidence has separate source, version, structure and projection identities. The
public contracts carry these identities into a citation address, together with an
anchor or selector, projection digest and the admitting tool-call identity.

A citation is useful only when it points into evidence that the run actually
admitted. Resolving a syntactically valid address is not enough: stale projections,
unseen evidence, mismatched selectors and quotes must not become accepted support.
Containment checks keep the selected span within the admitted evidence. Repair is
bounded and must not manufacture a source or silently strengthen an unsupported
claim. When the available evidence cannot support a claim, output an explicit gap.

## Reference formats

Markdown and text are interpreted as text evidence, not executed or rendered HTML.
Snapshots retain text and stable hierarchy identities independently of later file
changes. A caller deliberately selects input files; providers do not receive
arbitrary filesystem access. Hierarchy and citation fidelity for rich documents
are outside this adapter's scope.

Mechanical validity proves that an address and selected text match the admitted
snapshot. It does not prove that the text logically entails the generated claim.
Use independent evaluation or human review for that judgment.

## Text profile limits

The reference profile accepts safe `.md` and `.txt` labels, at most 1 MiB of UTF-8
source and 4,096 lines. Public canonical string records require NFC text; input that
cannot form those records is refused. A UTF-8 BOM stays in the source digest but is
removed from the projection. Line endings remain in projected text. Offsets count
decoded Unicode characters, not byte offsets.

The hierarchy contains a root, ATX heading sections outside fenced code, heading
leaves and nonblank line leaves. Sections include descendant text. This is a
bounded reference hierarchy, not a complete CommonMark AST or rendered Markdown
interpretation. Full-node citations use the canonical projected-string digest for
whole-node quote support. The reference tools do not admit arbitrary partial-span
citations merely because the public address schema can represent them.

Tool replies have a 65,536-byte normalized payload limit in addition to the retained
per-tool node, character, regex and call bounds. A failed reply admits no citations.
