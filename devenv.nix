{ pkgs, ... }:
{
  languages.go.enable = true;
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src" ];
  };
  packages = with pkgs; [
    git
    just
    syft
    nfpm
    nix
  ];

  enterTest = "just test";
}
