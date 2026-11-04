{
  description = "Bommer: configurable Linux bill-of-materials collection";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      package = pkgs.buildGoModule {
        pname = "bommer";
        version = "0.1.0-dev";
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            pkgs.lib.cleanSourceFilter path type
            && !(builtins.elem (baseNameOf path) [ ".devenv" ".direnv" "dist" "results" ]);
        };
        vendorHash = "sha256-g+yaVIx4jxpAQ/+WrGKxhVeliYx7nLQe/zsGpxV4Fn4=";
        subPackages = [ "cmd/bommer" ];
        env.CGO_ENABLED = 0;
        ldflags = [ "-s" "-w" "-X main.version=0.1.0-dev" ];
        nativeBuildInputs = [ pkgs.makeWrapper ];
        postInstall = ''
          wrapProgram $out/bin/bommer --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.syft ]}
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
