{
  description = "Bommer: configurable Linux bill-of-materials collection";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      toolchain = pkgs.rust-bin.stable.latest.default;
      rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
      package = rustPlatform.buildRustPackage {
        pname = "bommer";
        version = "0.1.0-dev";
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            pkgs.lib.cleanSourceFilter path type
            && !(builtins.elem (baseNameOf path) [ ".devenv" ".direnv" "dist" "target" "results" ]);
        };
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "--bin" "bommer" ];
        doCheck = true;
        nativeBuildInputs = [ pkgs.makeWrapper ];
        nativeCheckInputs = [ pkgs.gitMinimal pkgs.syft ];
        checkPhase = ''
          runHook preCheck
          cargo test --locked --release
          runHook postCheck
        '';
        postInstall = ''
          wrapProgram $out/bin/bommer --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.syft pkgs.gitMinimal pkgs.nix ]}
        '';
        meta = {
          description = "Configurable HBOM, SBOM, and application CBOM orchestration";
          homepage = "https://codeberg.org/Poellebob/bommer";
          mainProgram = "bommer";
          platforms = [ system ];
        };
      };
    in {
      packages.${system} = {
        default = package;
        bommer = package;
      };
      apps.${system}.default = {
        type = "app";
        program = "${package}/bin/bommer";
      };
      checks.${system}.bommer = package;
      nixosModules.default = import ./nix/module.nix self;
    };
}
