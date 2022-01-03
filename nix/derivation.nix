{ stdenv, lib, buildGoModule, git, makeWrapper, substituteAll, grpc, protobuf, pkgs, runCommand }:

buildGoModule rec {
  pname = "gorram";
  #version = "0.0.1";

  # dynamic version based on git; https://blog.replit.com/nix_dynamic_version
  revision = runCommand "get-rev" {
          nativeBuildInputs = [ git ];
      } "GIT_DIR=${src}/.git git rev-parse --short HEAD | tr -d '\n' > $out";  

  buildDate = runCommand "get-date" {} "date +'%Y-%m-%d_%T' | tr -d '\n' > $out"; 

  version = "0" + builtins.readFile revision;        

  src = ../.;

  nativeBuildInputs = [ 
    makeWrapper 
    grpc 
    protobuf 
    pkgs.protoc-gen-go
    pkgs.protoc-gen-go-grpc
  ];

  buildInputs = [ 
    git 
    grpc 
    protobuf 
    pkgs.protoc-gen-go
    pkgs.protoc-gen-go-grpc
  ];

  ldflags = [ "-X main.sha1ver=${version}" "-X main.buildTime=${builtins.readFile buildDate}" ];

  vendorSha256 = "0wpzgin13rgr3jlhi1mz54s8k0ifvwq8vgbpfagb7wjn7i2mbcda";

  runVend = false;

  deleteVendor = false;

  subPackages = [ "./proto" "./server" "./client" "./checks" "./cli" ];

  
  preBuild = ''
    protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/gorram.proto
  '';
  

  meta = with lib; {
    description = "A Gorram monitoring tool";
    homepage = "https://github.com/aqtrans/gorram";
    license = licenses.mit;
    maintainers = with maintainers; [ "aqtrans" ];
    platforms = platforms.linux;
  };
}
