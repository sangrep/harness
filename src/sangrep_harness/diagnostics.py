from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ProviderRequestFieldV1(StrEnum):
    """Closed top-level request field named by a sanitized provider diagnostic."""

    MODEL = "model"
    MESSAGES = "messages"
    MAX_COMPLETION_TOKENS = "max_completion_tokens"
    TOOLS = "tools"
    UNKNOWN = "unknown"


class ProviderBadRequestSubcodeV1(StrEnum):
    """Closed provider-independent interpretation of structured bad-request authority."""

    INVALID_REQUEST = "invalid_request"
    OTHER_BAD_REQUEST = "other_bad_request"


@dataclass(frozen=True, slots=True)
class ProviderFailureDiagnosticV1:
    """Versioned safe diagnostic triplet for one outcome-known bad request."""

    http_status: int
    request_field: ProviderRequestFieldV1
    bad_request_subcode: ProviderBadRequestSubcodeV1

    def __post_init__(self) -> None:
        if type(self.http_status) is not int or self.http_status not in {400, 409, 422}:
            raise ValueError("provider bad-request HTTP status is invalid")
        if type(self.request_field) is not ProviderRequestFieldV1:
            raise TypeError("request_field must use ProviderRequestFieldV1")
        if type(self.bad_request_subcode) is not ProviderBadRequestSubcodeV1:
            raise TypeError("bad_request_subcode must use ProviderBadRequestSubcodeV1")

    @classmethod
    def from_json_obj(cls, value: object) -> ProviderFailureDiagnosticV1:
        expected_fields = {
            "schemaVersion",
            "httpStatus",
            "requestField",
            "badRequestSubcode",
        }
        if (
            type(value) is not dict
            or any(type(field) is not str for field in value)
            or set(value) != expected_fields
        ):
            raise ValueError("provider failure diagnostic shape is invalid")
        if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
            raise ValueError("provider failure diagnostic version is invalid")
        if type(value["requestField"]) is not str or type(value["badRequestSubcode"]) is not str:
            raise ValueError("provider failure diagnostic value is invalid")
        try:
            request_field = ProviderRequestFieldV1(value["requestField"])
            subcode = ProviderBadRequestSubcodeV1(value["badRequestSubcode"])
            return cls(
                http_status=value["httpStatus"],
                request_field=request_field,
                bad_request_subcode=subcode,
            )
        except (TypeError, ValueError):
            raise ValueError("provider failure diagnostic value is invalid") from None

    def to_json_obj(self) -> dict[str, int | str]:
        return {
            "schemaVersion": 1,
            "httpStatus": self.http_status,
            "requestField": self.request_field.value,
            "badRequestSubcode": self.bad_request_subcode.value,
        }
