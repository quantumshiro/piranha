const std = @import("std");
const Builder = @import("std").build.Builder;

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Create common modules
    const crypto_mod = b.createModule(.{
        .root_source_file = b.path("src/common/crypto.zig"),
        .target = target,
        .optimize = optimize,
    });

    const signature_mod = b.createModule(.{
        .root_source_file = b.path("src/common/signature.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cell_mod = b.createModule(.{
        .root_source_file = b.path("src/common/cell.zig"),
        .target = target,
        .optimize = optimize,
    });

    const net_mod = b.createModule(.{
        .root_source_file = b.path("src/common/net.zig"),
        .target = target,
        .optimize = optimize,
    });

    // This creates a "module", which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Every executable or library we compile will be based on one or more modules.
    const lib_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add common module imports to lib_mod
    lib_mod.addImport("crypto", crypto_mod);
    lib_mod.addImport("signature", signature_mod);
    lib_mod.addImport("cell", cell_mod);
    lib_mod.addImport("net", net_mod);

    // We will also create a module for our other entry point, 'main.zig'.
    const exe_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create authority module
    const authority_mod = b.createModule(.{
        .root_source_file = b.path("src/authority/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create exit module
    const exit_mod = b.createModule(.{
        .root_source_file = b.path("src/exit/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create client module
    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/client/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add common module imports to exe_mod
    exe_mod.addImport("crypto", crypto_mod);
    exe_mod.addImport("signature", signature_mod);
    exe_mod.addImport("cell", cell_mod);
    exe_mod.addImport("net", net_mod);

    // Add common module imports to authority_mod
    authority_mod.addImport("crypto", crypto_mod);
    authority_mod.addImport("signature", signature_mod);
    authority_mod.addImport("cell", cell_mod);
    authority_mod.addImport("net", net_mod);

    // Add common module imports to exit_mod
    exit_mod.addImport("crypto", crypto_mod);
    exit_mod.addImport("signature", signature_mod);
    exit_mod.addImport("cell", cell_mod);
    exit_mod.addImport("net", net_mod);

    // Add common module imports to client_mod
    client_mod.addImport("crypto", crypto_mod);
    client_mod.addImport("signature", signature_mod);
    client_mod.addImport("cell", cell_mod);
    client_mod.addImport("net", net_mod);

    // Modules can depend on one another using the `std.Build.Module.addImport` function.
    // This is what allows Zig source code to use `@import("foo")` where 'foo' is not a
    // file path. In this case, we set up `exe_mod` to import `lib_mod`.
    exe_mod.addImport("piranha_lib", lib_mod);
    authority_mod.addImport("piranha_lib", lib_mod);
    exit_mod.addImport("piranha_lib", lib_mod);
    client_mod.addImport("piranha_lib", lib_mod);

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "piranha",
        .root_module = lib_mod,
    });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "piranha",
        .root_module = exe_mod,
    });

    // Create authority executable
    const authority_exe = b.addExecutable(.{
        .name = "piranha-authority",
        .root_module = authority_mod,
    });
    
    // Add authority executable using the requested format
    const auth = b.addExecutable(.{
        .name = "authority",
        .root_module = authority_mod,
    });
    auth.linkLibC();

    // Create exit executable
    const exit_exe = b.addExecutable(.{
        .name = "piranha-exit",
        .root_module = exit_mod,
    });

    // Add exit executable using the requested format
    const exit = b.addExecutable(.{
        .name = "exit",
        .root_module = exit_mod,
    });
    exit.linkLibC();

    // Create client executable
    const client_exe = b.addExecutable(.{
        .name = "piranha-client",
        .root_module = client_mod,
    });

    // Add client executable using the requested format
    const client = b.addExecutable(.{
        .name = "client",
        .root_module = client_mod,
    });
    client.linkLibC();

    // Web fetcher executable
    const fetch_exe = b.addExecutable(.{
        .name = "piranha-fetch",
        .root_source_file = b.path("src/piranha_fetch.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Add common module imports to fetch_exe
    fetch_exe.root_module.addImport("crypto", crypto_mod);
    fetch_exe.root_module.addImport("signature", signature_mod);
    fetch_exe.root_module.addImport("cell", cell_mod);
    fetch_exe.root_module.addImport("net", net_mod);
    fetch_exe.root_module.addImport("piranha_lib", lib_mod);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);
    b.installArtifact(authority_exe);
    b.installArtifact(auth);
    b.installArtifact(exit_exe);
    b.installArtifact(exit);
    b.installArtifact(client_exe);
    b.installArtifact(client);
    b.installArtifact(fetch_exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);
    const authority_run_cmd = b.addRunArtifact(authority_exe);
    const auth_run_cmd = b.addRunArtifact(auth);
    const exit_run_cmd = b.addRunArtifact(exit_exe);
    const exit_cmd = b.addRunArtifact(exit);
    const client_run_cmd = b.addRunArtifact(client_exe);
    const client_cmd = b.addRunArtifact(client);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());
    authority_run_cmd.step.dependOn(b.getInstallStep());
    auth_run_cmd.step.dependOn(b.getInstallStep());
    exit_run_cmd.step.dependOn(b.getInstallStep());
    exit_cmd.step.dependOn(b.getInstallStep());
    client_run_cmd.step.dependOn(b.getInstallStep());
    client_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
        authority_run_cmd.addArgs(args);
        auth_run_cmd.addArgs(args);
        exit_run_cmd.addArgs(args);
        exit_cmd.addArgs(args);
        client_run_cmd.addArgs(args);
        client_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const authority_run_step = b.step("run-authority", "Run the Directory Authority server");
    authority_run_step.dependOn(&authority_run_cmd.step);
    
    const auth_run_step = b.step("run-auth", "Run the authority executable");
    auth_run_step.dependOn(&auth_run_cmd.step);

    const exit_run_step = b.step("run-exit", "Run the Exit Node server");
    exit_run_step.dependOn(&exit_run_cmd.step);
    
    const exit_step = b.step("run-exit-node", "Run the exit node executable");
    exit_step.dependOn(&exit_cmd.step);

    const client_run_step = b.step("run-client", "Run the Piranha Client");
    client_run_step.dependOn(&client_run_cmd.step);
    
    const client_step = b.step("run-client-proxy", "Run the client proxy executable");
    client_step.dependOn(&client_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
