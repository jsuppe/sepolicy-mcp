import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sepolicy_mcp.server import (
    parse_denials_raw, suggest_macro, Denial,
    _parse_neverallow_body, _parse_set, _set_matches, _perms_match,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_dedupe():
    with open(os.path.join(FIXTURES, "denials_sample.log")) as f:
        denials = parse_denials_raw(f.read())
    # 5 lines -> 4 unique (2 binder:call collapse, transfer separate, sock_file, unix_stream)
    assert len(denials) == 4
    binder_call = [d for d in denials if d.tclass == "binder" and "call" in d.perms and "transfer" not in d.perms][0]
    assert binder_call.count == 2


def test_binder_macro():
    d = Denial("vcam_hal", "system_server", "binder", ("call", "transfer"), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro == "binder_call(vcam_hal, system_server)"


def test_service_manager_add():
    d = Denial("vcam_hal", "vcam_service", "service_manager", ("add",), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro == "add_service(vcam_hal, vcam_service)"


def test_hwservice_add():
    d = Denial("vcam_hal", "hal_camera_hwservice", "hwservice_manager", ("add",), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro == "add_hwservice(vcam_hal, hal_camera_hwservice)"


def test_property_set():
    d = Denial("vcam_hal", "vendor_prop", "property_service", ("set",), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro == "set_prop(vcam_hal, vendor_prop)"


def test_net_domain():
    d = Denial("vcam_hal", "node", "tcp_socket", ("create",), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro == "net_domain(vcam_hal)"


def test_rw_dir_file():
    d = Denial("vcam_hal", "shell_data_file", "file", ("read", "write"), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro == "rw_dir_file(vcam_hal, shell_data_file)"


def test_parse_neverallow_simple():
    r = _parse_neverallow_body("untrusted_app shell_data_file:file { read write }")
    assert r is not None
    assert "untrusted_app" in r["src"][0]
    assert "shell_data_file" in r["tgt"][0]
    assert "file" in r["classes"][0]
    assert {"read", "write"}.issubset(r["perms"][0])


def test_parse_neverallow_set_with_exclusions():
    r = _parse_neverallow_body("{ domain -init } self:capability *")
    assert "domain" in r["src"][0]
    assert "init" in r["src"][1]  # excluded
    assert r["perms"][2] is True  # wildcard


def test_parse_neverallow_wildcards():
    r = _parse_neverallow_body("appdomain *:process ptrace")
    assert r["tgt"][2] is True  # wildcard target


def test_set_matches_wildcard():
    s = _parse_set("*")
    assert _set_matches(s, "anything") is True


def test_set_matches_excludes():
    s = _parse_set("{ a b -c }")
    assert _set_matches(s, "a") is True
    assert _set_matches(s, "c") is False
    assert _set_matches(s, "d") is False


def test_perms_match_alias():
    p = _parse_set("no_rw_file_perms")
    assert _perms_match(p, "read") is True
    assert _perms_match(p, "write") is True
    assert _perms_match(p, "execute") is False


def test_no_macro_for_unknown():
    d = Denial("vcam_hal", "random_t", "capability", ("sys_admin",), 1, set(), set())
    macro, _ = suggest_macro(d)
    assert macro is None


if __name__ == "__main__":
    test_dedupe()
    test_binder_macro()
    test_service_manager_add()
    test_hwservice_add()
    test_property_set()
    test_net_domain()
    test_rw_dir_file()
    test_no_macro_for_unknown()
    test_parse_neverallow_simple()
    test_parse_neverallow_set_with_exclusions()
    test_parse_neverallow_wildcards()
    test_set_matches_wildcard()
    test_set_matches_excludes()
    test_perms_match_alias()
    print("OK")
