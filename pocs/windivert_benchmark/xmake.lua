-- WinDivert benchmark tool, the Windows counterpart of pocs/linux_kernel_module_backend (swbench). Not built by default:
-- `xmake build wdbench`. Run it through bench.ps1 (see its header).
if is_plat("windows") then
    target("wdbench")
        set_kind("binary")
        set_default(false)
        add_files("wdbench.cc")
        add_includedirs("../../win_divert/include")
        add_linkdirs("../../win_divert/x64")
        add_links("WinDivert", "ws2_32", "winmm")
        -- WinDivert.dll loads WinDivert64.sys from its own directory
        after_build(function (target)
            -- the driver file is locked while WinDivert is loaded from here; a stale copy is the same version
            for _, file in ipairs({"WinDivert.dll", "WinDivert64.sys"}) do
                try { function () os.cp(path.join(os.scriptdir(), "..", "..", "win_divert", "x64", file), target:targetdir()) end }
            end
        end)
    target_end()
end
