import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sepolicy_mcp.server import parse_denials_raw, suggest_macro, Denial

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
    print("OK")
