-- Regression tests for the profiles YAML loader. Build and run with `xmake build options_test && xmake run options_test`.
target("options_test")
    set_kind("binary")
    set_default(false)
    set_rundir(os.projectdir())
    add_files("options_test.cc")
    add_files("../../src/log.cc", "../../src/options/util.cc", "../../src/options/profiles.cc", "../../src/options/validate.cc")
    add_includedirs("../../include", "../../src")
