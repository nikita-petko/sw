-- `xmake format` rewrites every first-party C/C++ source in place according to .clang-format.
-- `xmake format --check` only reports files that need formatting and fails if there are any (for CI).
task("format")
    set_category("plugin")
    set_menu {
        usage = "xmake format [options]",
        description = "Format all sources according to the .clang-format rules.",
        options = {
            {'c', "check", "k", nil, "Do not modify files; fail if any file is not formatted."},
            {nil, "clang-format", "kv", "clang-format", "The clang-format executable to use."}
        }
    }
    on_run(function ()
        import("core.base.option")
        import("lib.detect.find_program")

        local root = os.projectdir()
        local program = find_program(option.get("clang-format"))
        if not program then
            raise("clang-format not found, install it or pass --clang-format=<path>")
        end

        -- Vendored (win_divert) and generated (build, dist, .xmake, .cache) directories are not ours to format
        local roots = {"backends", "include", "pocs", "src", "tests"}
        local patterns = {"*.cc", "*.cpp", "*.c", "*.h", "*.hpp"}
        local files = {}
        for _, dir in ipairs(roots) do
            for _, pattern in ipairs(patterns) do
                for _, file in ipairs(os.files(path.join(root, dir, "**", pattern))) do
                    table.insert(files, file)
                end
            end
        end
        table.sort(files)
        if #files == 0 then
            print("no source files found")
            return
        end

        local check = option.get("check")
        local failed = {}
        for _, file in ipairs(files) do
            local relative = path.relative(file, root)
            if check then
                local ok = try { function ()
                    os.runv(program, {"--style=file", "--dry-run", "--Werror", file}, {curdir = root})
                    return true
                end }
                if not ok then
                    table.insert(failed, relative)
                end
            else
                os.runv(program, {"--style=file", "-i", file}, {curdir = root})
            end
        end

        if check then
            if #failed > 0 then
                cprint("${color.error}%d of %d files need formatting:", #failed, #files)
                for _, file in ipairs(failed) do
                    print("  " .. file)
                end
                raise("run `xmake format` to fix")
            end
            cprint("${color.success}all %d files are formatted", #files)
        else
            cprint("${color.success}formatted %d files", #files)
        end
    end)
task_end()
