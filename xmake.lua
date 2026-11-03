-- Project-wide settings live in modules/, split by concern; see each file.
includes("modules/build_mode.lua")
includes("modules/toolchain.lua")
apply_build_mode()
apply_toolchain()

-- Feature options must be declared before any target that opts in with add_options()
includes("modules/features.lua")
includes("modules/backends.lua")
includes("modules/app.lua")
includes("modules/tests.lua")
includes("modules/pocs.lua")
includes("modules/format.lua")
includes("modules/package_all.lua")
