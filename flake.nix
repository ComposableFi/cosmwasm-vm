{
  description = "Cosmwasm VM";
  inputs = {
    nixpkgs.url =
      "github:NixOS/nixpkgs/60ddbcfc9e5f02f97564fa01a5646b62d82e0756";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ fenix.overlay ];
        };
      in {
        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.pkg-config
            pkgs.openssl
            pkgs.stdenv.cc.cc
            (pkgs.fenix.latest.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
            ])
          ];
          RUST_LOG = "debug";
        };
      });
}
