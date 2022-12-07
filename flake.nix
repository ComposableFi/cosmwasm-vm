{
  description = "Cosmwasm VM";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };
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
        # Nightly rust used for wasm runtime compilation
        rust-stable =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Crane lib instantiated with current nixpkgs
        crane-lib = crane.mkLib pkgs;

        # Crane pinned to nightly Rust
        crane-stable = crane-lib.overrideToolchain rust-stable;

        src = pkgs.lib.cleanSourceWith {
          filter = pkgs.lib.cleanSourceFilter;
          src = pkgs.lib.cleanSourceWith {
            filter = pkgs.nix-gitignore.gitignoreFilterPure (name: type: true)
              [ ./.gitignore ] ./.;
            src = ./.;
          };
        };

        # Default args to crane
        common-args = {
          inherit src;
          buildInputs = [ pkgs.pkg-config pkgs.openssl ]
            ++ (pkgs.lib.optionals pkgs.stdenv.isDarwin
              (with pkgs.darwin.apple_sdk.frameworks; [ Security ]));
        };

        # Common dependencies used for caching
        common-deps = crane-stable.buildDepsOnly common-args;

        common-cached-args = common-args // { cargoArtifacts = common-deps; };

      in rec {
        packages = rec {
          cosmwasm-vm = crane-stable.buildPackage common-cached-args;
          default = cosmwasm-vm;
        };
        checks = {
          package = packages.default;
          clippy = crane-stable.cargoClippy (common-cached-args // {
            cargoClippyExtraArgs = "-- --deny warnings";
          });
          fmt = crane-stable.cargoFmt common-args;
        };
        devShell = pkgs.mkShell {
          buildInputs = [ rust-stable ]
            ++ (with pkgs; [ openssl openssl.dev pkgconfig taplo nixfmt bacon ]);
        };
      });
}
