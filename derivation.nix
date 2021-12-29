{ stdenv, lib, buildGoModule, git, makeWrapper, substituteAll, grpc, protobuf }:

buildGoModule rec {
  pname = "gorram";
  version = "0.0.1";

  src = ./.;

  nativeBuildInputs = [ makeWrapper grpc protobuf ];

  buildInputs = [ git grpc protobuf ];

  vendorSha256 = null;

  runVend = false;

  deleteVendor = false;

  subPackages = [ "./server" "./client" ];

  /*
  preBuild = ''
    substituteInPlace main.go --replace 'gitPath, err := exec.LookPath("git")' 'gitPath, err := exec.LookPath("${git}/bin/git")'
    substituteInPlace main_test.go --replace 'gitPath, err := exec.LookPath("git")' 'gitPath, err := exec.LookPath("${git}/bin/git")'
  '';
  */

  meta = with lib; {
    description = "A Gorram monitoring tool";
    homepage = "https://github.com/aqtrans/gorram";
    license = licenses.mit;
    maintainers = with maintainers; [ aqtrans ];
    platforms = platforms.linux;
  };
}
