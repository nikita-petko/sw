-- Settings are wrapped in a function and called from the root xmake.lua. Statements made at the top level of an
-- included file only apply to targets in that file's own scope, not to the targets of the files included after it.
function apply_build_mode()
    add_rules("mode.debug", "mode.release")

    set_policy("build.ccache", false)

    if is_mode("release") then
        set_policy("build.optimization.lto", true)

        set_optimize("fastest")
        add_defines("NDEBUG", "_NDEBUG")

        set_strip("all")
    end

    if is_mode("debug") then
        add_defines("DEBUG", "_DEBUG")
    end
end
