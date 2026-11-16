import json

import pytest

from src.parser import EventParser, parse_cloudtrail_event, parse_event, parse_flow_log


FLOW_LINE = (
    "2 123456789012 eni-0123456789abcdef0 10.0.1.10 10.0.2.20 "
    "51524 443 6 12 8420 1731501000 1731501060 ACCEPT OK"
)


def test_parse_standard_vpc_flow_log_fields():
    event = parse_flow_log(FLOW_LINE)

    assert event["event_type"] == "NETWORK_FLOW"
    assert event["source_ip"] == "10.0.1.10"
    assert event["destination_ip"] == "10.0.2.20"
    assert event["source_port"] == 51524
    assert event["destination_port"] == 443
    assert event["protocol"] == 6
    assert event["packets"] == 12
    assert event["bytes"] == 8420
    assert event["action"] == "ACCEPT"
    assert event["log_status"] == "OK"
    assert event["timestamp"].startswith("2024-11-13T")


def test_parse_flow_log_handles_dash_as_missing_integer():
    line = FLOW_LINE.replace("51524", "-")
    event = parse_flow_log(line)
    assert event["source_port"] is None


def test_parse_flow_log_rejects_wrong_field_count():
    with pytest.raises(ValueError, match="values"):
        parse_flow_log("2 123456789012 eni-123")


def test_parse_flow_log_rejects_non_string_input():
    with pytest.raises(TypeError):
        parse_flow_log(123)  # type: ignore[arg-type]


def test_parse_cloudtrail_event():
    payload = {
        "eventTime": "2025-01-01T10:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "sourceIPAddress": "198.51.100.10",
        "recipientAccountId": "123456789012",
        "awsRegion": "ap-south-1",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/test"},
        "requestParameters": {"userName": "test"},
    }

    event = parse_cloudtrail_event(payload)

    assert event["event_type"] == "AWS_API"
    assert event["event_name"] == "CreateAccessKey"
    assert event["event_source"] == "iam.amazonaws.com"
    assert event["source_ip"] == "198.51.100.10"
    assert event["destination_port"] is None
    assert event["user_type"] == "IAMUser"


def test_parse_event_accepts_json_cloudtrail_string():
    payload = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "sourceIPAddress": "203.0.113.5",
    }
    event = parse_event(json.dumps(payload))
    assert event["event_type"] == "AWS_API"
    assert event["event_name"] == "AuthorizeSecurityGroupIngress"


def test_event_parser_parses_many_and_cloudwatch_metadata():
    parser = EventParser()
    parsed = parser.parse_many([
        FLOW_LINE,
        {"message": FLOW_LINE, "timestamp_ms": 1731501060000, "event_id": "abc"},
    ])

    assert len(parsed) == 2
    assert parsed[1]["collector_metadata"]["event_id"] == "abc"
    assert parsed[1]["timestamp"].startswith("2024-11-13T")


def test_parse_event_rejects_invalid_json_and_empty_message():
    with pytest.raises(ValueError, match="invalid"):
        parse_event('{"eventName":')
    with pytest.raises(ValueError, match="empty"):
        parse_event("   ")
