from monitor.detect import analyze_route, normalize_as_path


def test_authorized_exact_prefix_is_accepted():
    analysis = analyze_route("192.168.100.0/24", [100])

    assert not analysis.suspicious
    assert analysis.origin_as == 100
    assert analysis.reason == "Route accepted"


def test_more_specific_from_attacker_origin_is_suspicious():
    analysis = analyze_route("192.168.100.0/25", [300])

    assert analysis.suspicious
    assert analysis.origin_as == 300
    assert analysis.rule == "unauthorized_origin"


def test_suspicious_transit_asn_is_detected_with_legitimate_origin():
    analysis = analyze_route("192.168.100.0/24", [200, 300, 100])

    assert analysis.suspicious
    assert analysis.origin_as == 100
    assert analysis.rule == "suspicious_transit_asn"


def test_outside_protected_prefix_does_not_trigger():
    analysis = analyze_route("192.168.200.0/24", [300])

    assert not analysis.suspicious
    assert not analysis.touches_protected


def test_exabgp_segmented_as_path_is_preserved_in_order():
    raw_as_path = {"0": {"element": "as-sequence", "value": [200, 300, 100]}}

    assert normalize_as_path(raw_as_path) == [200, 300, 100]
