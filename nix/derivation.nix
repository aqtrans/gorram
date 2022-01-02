with import <nixpkgs> {};

{ stdenv, lib, buildGoModule, git, makeWrapper, substituteAll, grpc, protobuf, pkgs }:

buildGoModule rec {
  name = "gorram";
  #version = "0.0.1";

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

  vendorSha256 = "0wpzgin13rgr3jlhi1mz54s8k0ifvwq8vgbpfagb7wjn7i2mbcda";

  runVend = false;

  deleteVendor = false;

  subPackages = [ "./proto" "./server" "./client" "./checks" ];

  
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
