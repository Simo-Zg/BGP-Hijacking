from monitor.detect import is_more_specific_hijack, touches_protected_space


def test_first_half_more_specific_inside_protected_prefix():
    assert touches_protected_space("192.168.100.0/25")
    assert is_more_specific_hijack("192.168.100.0/25")


def test_second_half_more_specific_inside_protected_prefix():
    assert touches_protected_space("192.168.100.128/25")
    assert is_more_specific_hijack("192.168.100.128/25")


def test_adjacent_prefix_does_not_touch_protected_prefix():
    assert not touches_protected_space("192.168.101.0/24")
    assert not is_more_specific_hijack("192.168.101.0/24")
