{
  description = "dnscheck — DNS privacy analyzer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dnscheck = pkgs.rustPlatform.buildRustPackage {
          pname = "dnscheck";
          version = "0.1.0";
          src = ./.;
          cargoLock = { lockFile = ./Cargo.lock; };
          meta = with pkgs.lib; {
            description = "DNS privacy analyzer";
            license = licenses.mit;
            maintainers = [ ];
            mainProgram = "dnscheck";
          };
        };
      in {
        packages.default = dnscheck;
        packages.dnscheck = dnscheck;
        apps.default = flake-utils.lib.mkApp { drv = dnscheck; };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ rustc cargo rustfmt clippy pkg-config ];
        };
      });
}
