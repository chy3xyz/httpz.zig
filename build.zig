const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Translate C headers for OpenSSL
    const openssl_c = b.addTranslateC(.{
        .root_source_file = b.path("src/openssl.h"),
        .target = target,
        .optimize = optimize,
    });
    openssl_c.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
    const openssl_c_mod = openssl_c.createModule();

    // Library module
    const httpz_mod = b.addModule("httpz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "openssl_c", .module = openssl_c_mod },
        },
    });
    httpz_mod.linkSystemLibrary("ssl", .{});
    httpz_mod.linkSystemLibrary("crypto", .{});
    httpz_mod.link_libc = true;

    // Example executables
    const examples = [_][]const u8{
        "client_http",
        "client_https",
        "server_http",
        "server_https",
        "server_websocket",
        "server_router",
        "server_streaming",
        "server_repro",
    };

    inline for (examples) |name| {
        const example_mod = b.createModule(.{
            .root_source_file = b.path("examples/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "httpz", .module = httpz_mod },
            },
        });
        const example_exe = b.addExecutable(.{
            .name = name,
            .root_module = example_mod,
        });
        b.installArtifact(example_exe);

        const run_step = b.step("example_" ++ name, "Run the " ++ name ++ " example");
        const run_cmd = b.addRunArtifact(example_exe);
        run_step.dependOn(&run_cmd.step);
        run_cmd.step.dependOn(b.getInstallStep());
    }

    // Module tests
    const mod_tests = b.addTest(.{
        .root_module = httpz_mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Integration tests
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "httpz", .module = httpz_mod },
            },
        }),
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Integration test step (separate because they use networking)
    const integration_step = b.step("test-integration", "Run integration tests");
    integration_step.dependOn(&run_integration_tests.step);

    // Test step
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    // Coverage step using kcov
    const coverage_step = b.step("coverage", "Run tests with kcov code coverage");

    // Module tests cover everything via refAllDecls in root.zig
    const cov_mod_test = b.addTest(.{
        .root_module = httpz_mod,
        .use_llvm = true,
        .use_lld = true,
    });

    const kcov_mod = b.addSystemCommand(&.{"kcov"});
    kcov_mod.addPrefixedDirectoryArg("--include-path=", b.path("src"));
    kcov_mod.addArg("kcov-output");
    kcov_mod.addArtifactArg(cov_mod_test);
    coverage_step.dependOn(&kcov_mod.step);

}
