{
  description = "Cosmwasm VM";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };
  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      in let
        rust-nightly =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        crane-lib = crane.mkLib pkgs;

        crane-nightly = crane-lib.overrideToolchain rust-nightly;

        features = " --features iterator";
        package="cosmwasm-vm";
        check-no-std = pkgs.writeShellApplication rec {
          name = "check-no-std";
          runtimeInputs = [ rust-nightly ];
          text = ''
            cargo build --locked --no-default-features --target thumbv7em-none-eabi --package ${package} ${features}
          '';
        };
        check-wasm-std = pkgs.writeShellApplication rec {
          name = "check-wasm-std";
          runtimeInputs = [ rust-nightly ];
          text = ''
            cargo build --target wasm32-unknown-unknown --locked ${features},std --package ${package}
          '';
        };
        
        src = pkgs.lib.cleanSourceWith {
          filter = pkgs.lib.cleanSourceFilter;
          src = pkgs.lib.cleanSourceWith {
            filter = pkgs.nix-gitignore.gitignoreFilterPure (name: type: true)
              [ ./.gitignore ] ./.;
            src = ./.;
          };
        };

        common-args = {
          inherit src;
          buildInputs = [ pkgs.pkg-config pkgs.openssl ]
            ++ (pkgs.lib.optionals pkgs.stdenv.isDarwin
              (with pkgs.darwin.apple_sdk.frameworks; [ Security ]));
        };

        common-deps = crane-nightly.buildDepsOnly common-args;
        common-cached-args = common-args // { cargoArtifacts = common-deps; };

      in rec {
        packages = rec {
          cosmwasm-vm = crane-nightly.buildPackage common-cached-args;
          default = cosmwasm-vm;
        };
        checks = {
          package = packages.default;
          clippy = crane-nightly.cargoClippy (common-cached-args // {
            cargoClippyExtraArgs = "-- --deny warnings";
          });
          fmt = crane-nightly.cargoFmt common-args;
        };
        devShell = pkgs.mkShell {
          buildInputs = [ rust-nightly ]
            ++ (with pkgs; [ openssl openssl.dev pkgconfig taplo nixfmt bacon flamegraph cargo-flamegraph check-no-std check-wasm-std]);
        };
      });
}
