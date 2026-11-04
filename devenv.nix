{ pkgs, ... }:
{
  languages.go.enable = true;
  packages = with pkgs; [
    git
    just
    syft
    nfpm
  ];

  enterTest = "just test";
}
