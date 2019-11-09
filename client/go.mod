module gorram/client

go 1.13

require (
	git.jba.io/go/gorram/certs v0.0.0-00010101000000-000000000000
	git.jba.io/go/gorram/checks v0.0.0-00010101000000-000000000000
	git.jba.io/go/gorram/proto v0.0.0-00010101000000-000000000000
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/pelletier/go-toml v1.2.0
	github.com/shirou/gopsutil v2.18.13-0.20190301133041-6c6abd6d1666+incompatible // indirect
	github.com/sirupsen/logrus v1.4.2
	google.golang.org/grpc v1.25.1
	gopkg.in/yaml.v2 v2.2.5 // indirect
)

replace (
	git.jba.io/go/gorram/certs => ../certs
	git.jba.io/go/gorram/checks => ../checks
	git.jba.io/go/gorram/proto => ../proto
)
