"""Android path attribution and layout detection — no assumption that any directory exists."""

import pytest

from android_forensics.filesystem.android_paths import COMMON_USER_ROOTS, analyze_layout, is_app_subdir


def locate(path, *others):
    return analyze_layout([path, *others]).locate(path)


# ------------------------------------------------------------------ the common Android paths


def test_data_data():
    a = locate("data/data/com.example.app/databases/app.db")
    assert (a.logical_path, a.root, a.area, a.user_id, a.package) == ("/data/data/com.example.app/databases/app.db", "data/data", "app_internal", None, "com.example.app")
    assert a.app_root == "data/data/com.example.app" and a.acquisition_root == ""


@pytest.mark.parametrize("path,user", [("data/user/0/com.x/files/f", 0), ("data/user/10/com.x/files/f", 10), ("data/user_de/0/com.x/f", 0)])
def test_data_user_with_user_ids(path, user):
    a = locate(path)
    assert a.user_id == user and a.package == "com.x" and a.root in ("data/user", "data/user_de")
    assert a.area in ("app_internal", "app_internal_de")


def test_data_user_needs_a_numeric_user_id():
    assert locate("data/user/notanumber/com.x/f").root is None


@pytest.mark.parametrize("path,root", [
    ("storage/emulated/0/DCIM/a.jpg", "storage/emulated"), ("storage/emulated/10/Download/x", "storage/emulated"),
    ("sdcard/DCIM/a.jpg", "sdcard"), ("sdcard0/x", "sdcard0"), ("mnt/sdcard/x", "mnt/sdcard"), ("mnt/user/0/primary/x", "mnt/user"),
    ("storage/self/primary/x", "storage/self/primary"), ("storage/sdcard1/x", "storage/sdcard1"), ("data/media/0/Pictures/x", "data/media"),
    ("storage/1A2B-3C4D/DCIM/x.jpg", "storage/external"),
])
def test_shared_and_external_storage_roots(path, root):
    a = locate(path)
    assert a.root == root and a.area == "shared_storage"


def test_app_specific_external_storage():
    a = locate("storage/emulated/0/Android/data/com.example.app/files/log.txt")
    assert (a.package, a.area, a.app_root) == ("com.example.app", "app_external", "storage/emulated/0/Android/data/com.example.app")
    assert locate("sdcard/Android/media/com.x/y").package == "com.x"
    assert locate("sdcard/Android/obb/com.x/main.obb").package == "com.x"
    assert locate("sdcard/Android/data").package is None


@pytest.mark.parametrize("path,root", [("data/system/users/0.xml", "data/system"), ("data/system_ce/0/x", "data/system_ce"),
                                        ("data/misc/wifi/x", "data/misc"), ("data/misc_ce/0/x", "data/misc_ce")])
def test_system_areas(path, root):
    a = locate(path)
    assert a.root == root and a.area == "system" and a.package is None


def test_apk_directories_old_and_new_style():
    old = locate("data/app/com.example.app-1/base.apk")
    new = locate("data/app/~~AbCdEf==/com.example.app-XyZ123==/base.apk")
    for a in (old, new):
        assert (a.package, a.area, a.root) == ("com.example.app", "app_binary", "data/app")
    assert new.app_root == "data/app/~~AbCdEf==/com.example.app-XyZ123=="
    assert locate("data/app/random-file").package is None


def test_logical_path_is_what_the_device_would_show():
    assert locate("userdata/data/data/com.a/f").logical_path == "/data/data/com.a/f"
    assert locate("a/b/sdcard/DCIM/x").logical_path == "/sdcard/DCIM/x"


# ------------------------------------------------------------------ unusual layouts


def test_a_dump_below_an_arbitrary_prefix():
    lay = analyze_layout(["userdata/data/data/com.a/databases/x.db", "userdata/sdcard/x", "userdata/system/build.prop"])
    assert lay.layout == "android_root_with_prefix" and [r.prefix for r in lay.roots] == ["userdata"]
    assert lay.locate("userdata/system/build.prop").root == "system", "top-level roots inside a recognised dump are honoured"
    assert lay.locate("userdata/data/data/com.a/databases/x.db").acquisition_root == "userdata"


def test_several_dumps_in_one_evidence_tree_are_kept_apart():
    lay = analyze_layout(["phoneA/data/data/com.a/a.db", "phoneB/data/data/com.a/a.db", "phoneB/sdcard/x", "notes.txt"])
    assert lay.layout == "multiple_roots" and sorted(r.prefix for r in lay.roots) == ["phoneA", "phoneB"]
    assert {r.prefix: r.files for r in lay.roots} == {"phoneA": 1, "phoneB": 2}
    assert lay.locate("phoneA/data/data/com.a/a.db").app_root == "phoneA/data/data/com.a"
    assert lay.locate("phoneB/data/data/com.a/a.db").app_root == "phoneB/data/data/com.a"
    assert lay.locate("notes.txt").root is None


def test_a_dump_that_holds_only_a_fragment_of_the_filesystem():
    assert analyze_layout(["sdcard/a.txt"]).layout == "android_root"
    lay = analyze_layout(["data/data/com.a/f"])
    assert lay.roots_present == ["data/data"] and set(lay.roots_absent) == set(COMMON_USER_ROOTS) - {"data/data"}


def test_missing_standard_roots_are_reported_not_treated_as_errors():
    lay = analyze_layout(["storage/emulated/0/DCIM/a.jpg"])
    assert lay.roots_present == ["storage/emulated"] and "data/data" in lay.roots_absent and "sdcard" in lay.roots_absent
    assert lay.layout == "android_root"


def test_bare_application_directories_without_any_android_root():
    lay = analyze_layout(["com.foo/databases/a.db", "com.foo/cache/x", "com.bar/files/y", "com.baz/app_flutter/z"])
    assert lay.layout == "app_directories"
    assert lay.locate("com.foo/cache/x").package == "com.foo", "an app's own cache directory is not a cache partition"
    assert lay.locate("com.foo/cache/x").root is None and lay.locate("com.foo/cache/x").app_root == "com.foo"
    assert lay.locate("com.baz/app_flutter/z").package == "com.baz"


def test_weak_roots_only_count_at_the_top_of_a_dump():
    lay = analyze_layout(["data/data/com.a/f", "system/build.prop", "vendor/lib/x.so", "cache/recovery/log"])
    assert [lay.locate(p).root for p in ("system/build.prop", "vendor/lib/x.so", "cache/recovery/log")] == ["system", "vendor", "cache"]
    deep = analyze_layout(["projects/system/notes.txt", "misc.bin"])
    assert deep.locate("projects/system/notes.txt").root is None, "a folder named 'system' inside examiner folders is not Android's"


def test_markers_are_matched_case_insensitively_for_tools_that_capitalise():
    a = locate("Data/Data/com.example.app/databases/x.db")
    assert a.root == "data/data" and a.package == "com.example.app"


def test_loose_and_single_file_inputs():
    assert analyze_layout(["notes/a.txt", "b.bin"]).layout == "loose_files"
    assert analyze_layout(["only.db"]).layout == "single_file"
    assert analyze_layout([]).layout == "loose_files"


def test_path_components_that_merely_resemble_markers_are_not_matched():
    for p in ("sdcards/x", "data/datas/com.x/f", "storagex/emulated/0/f", "mnt/users/0/f", "data/users/0/com.x/f"):
        assert locate(p).root is None


def test_empty_directories_still_reveal_roots_and_applications():
    lay = analyze_layout(["sdcard/a.txt"], directories=["data/data", "data/data/com.empty.app", "data/data/com.empty.app/databases"])
    assert "data/data" in lay.roots_present
    a = lay.locate("data/data/com.empty.app")
    assert a.app_root == "data/data/com.empty.app" and a.package == "com.empty.app"


def test_app_subdirectory_names():
    for name in ("databases", "shared_prefs", "files", "cache", "code_cache", "no_backup", "app_webview", "app_flutter", "app_x"):
        assert is_app_subdir(name)
    for name in ("app_", "misc", "Documents"):
        assert not is_app_subdir(name)


def test_locating_is_deterministic_and_never_raises():
    paths = ["", "/", "a//b", "data/data", "data/data/", "storage", "storage/emulated", "Android/data/com.x", "é/☃"]
    lay = analyze_layout(paths)
    assert [lay.locate(p) for p in paths] == [lay.locate(p) for p in paths]
