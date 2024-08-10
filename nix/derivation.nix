{ stdenv, lib, buildGoModule, git, makeWrapper, substituteAll, protobuf, pkgs, runCommandLocal }:

buildGoModule rec {
  pname = "gorram";
  #version = "0.0.1";

  # dynamic version based on git; https://blog.replit.com/nix_dynamic_version
  revision = runCommandLocal "get-rev" {
          nativeBuildInputs = [ git ];
      } "GIT_DIR=${src}/.git git rev-parse --short HEAD | tr -d '\n' > $out";  

  buildDate = runCommandLocal "get-date" {} "date +'%Y-%m-%d_%T' | tr -d '\n' > $out"; 

  version = "0" + builtins.readFile revision;        

  src = ../.;

  nativeBuildInputs = [ 
    makeWrapper 
    protobuf 
    pkgs.protoc-gen-go
    pkgs.protoc-gen-twirp
  ];

  buildInputs = [ 
    git 
    protobuf 
    pkgs.protoc-gen-go
    pkgs.protoc-gen-twirp
  ];

  ldflags = [ "-X main.sha1ver=${builtins.readFile revision}" "-X main.buildTime=${builtins.readFile buildDate}" ];

  vendorSha256 = "08h7r7lk72b8c6bx227v5s015dlb0zfr63k9g63x3zz2abjlg8i8";

  runVend = false;

  deleteVendor = false;

  subPackages = [ "./proto" "./server" "./client" "./checks" "./cli" ];

  
  preBuild = ''
    protoc --go_out=. --go_opt=paths=source_relative --twirp_out=. --twirp_opt=paths=source_relative proto/gorram.proto
  '';
  

  meta = with lib; {
    description = "A Gorram monitoring tool";
    homepage = "https://git.sr.ht/~aqtrans/gorram";
    license = licenses.mit;
    maintainers = with maintainers; [ "aqtrans" ];
    platforms = platforms.linux;
  };
}
