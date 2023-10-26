{ pkgs, ... }:

{
  packages = with pkgs; [git];

  languages.python = {
    enable = true;
    package = pkgs.pypy3;
    poetry.enable = true;
  };
}
