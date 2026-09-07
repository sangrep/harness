"""Component-local review values remain subordinate to the accepted public contracts."""

from copy import deepcopy
from dataclasses import replace

import pytest
from sangrep_contracts import CitationAddressV1, ContractValidationError, EvidenceNodeV1

from sangrep_harness import ExtractiveFakeProviderV1, review_snapshot_v1, snapshot_text_v1
from sangrep_harness.evidence_head import text_evidence_head_v1
from sangrep_harness.review import (
    EvidenceIdentityDraftsV1,
    ReviewSemanticError,
    _validate_citation_address_shape,
)
from sangrep_harness.wire import canonical_json_sha256_v1


@pytest.mark.parametrize(
    "mutation", ["unknown-field", "wrong-version", "wrong-selector", "reversed-range", "bad-digest"]
)
def test_citation_rejections_agree_with_public_contract(mutation):
    snapshot = snapshot_text_v1(b"Only observers enter.\n", relative_path="a.txt")
    result = review_snapshot_v1(
        snapshot, question="Quote rule", provider=ExtractiveFakeProviderV1()
    )
    value = deepcopy(result.draft.citations[0].address.to_json_obj())
    if mutation == "unknown-field":
        value["untrusted"] = True
    elif mutation == "wrong-version":
        value["schemaVersion"] = 2
    elif mutation == "wrong-selector":
        value["selector"] = {"kind": "node", "anchorId": "different"}
    elif mutation == "reversed-range":
        value["selector"] = {"kind": "lineRange", "startLine": 2, "endLine": 1}
    else:
        value["projectionPayloadSha256"] = "invalid"
    with pytest.raises(ContractValidationError):
        CitationAddressV1.from_json_obj(value)
    with pytest.raises(ReviewSemanticError):
        _validate_citation_address_shape(value)


def test_mixed_public_identity_records_are_rejected():
    first = snapshot_text_v1(b"First evidence\n", relative_path="a.txt")
    second = snapshot_text_v1(b"Second evidence\n", relative_path="a.txt")
    with pytest.raises(ReviewSemanticError):
        EvidenceIdentityDraftsV1.from_json_obj(
            {
                "evidenceVersion": first.evidence.to_json_obj(),
                "structureRevision": second.structure.to_json_obj(),
                "projectionRevision": first.projection.to_json_obj(),
            }
        )


def test_valid_contract_node_with_cyclic_parent_cannot_form_text_authority():
    snapshot = snapshot_text_v1(b"A line\n", relative_path="a.txt")
    node = snapshot.nodes[1].to_json_obj()
    node["parentAnchorId"] = node["anchorId"]
    node["parentOccurrenceId"] = node["occurrenceId"]
    del node["canonicalNodeSha256"]
    node["canonicalNodeSha256"] = canonical_json_sha256_v1(node)
    cyclic = EvidenceNodeV1.from_json_obj(node)
    with pytest.raises(ValueError, match="snapshot-authority"):
        text_evidence_head_v1(replace(snapshot, nodes=(snapshot.nodes[0], cyclic)))
