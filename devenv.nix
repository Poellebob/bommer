{ pkgs, ... }:
{
  languages.go.enable = true;
  packages = with pkgs; [
    git
    just
    syft
    nfpm
    nix
  ];

  enterTest = "just test";
}
