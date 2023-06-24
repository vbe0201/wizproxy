{ pkgs, ... }:

{
  packages = with pkgs; [git];

  languages.python = {
    enable = true;
    package = pkgs.python311;
    poetry.enable = true;
  };
}
