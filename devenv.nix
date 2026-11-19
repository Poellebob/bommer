{ pkgs, ... }:
{
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src" ];
    targets = [ "x86_64-unknown-linux-musl" ];
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
