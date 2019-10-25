module gorram/client

go 1.13

require (
	git.jba.io/go/gorram/certs v0.0.0-00010101000000-000000000000
	git.jba.io/go/gorram/checks v0.0.0-00010101000000-000000000000
	git.jba.io/go/gorram/proto v0.0.0-00010101000000-000000000000
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6
	github.com/go-ole/go-ole v1.2.4
	github.com/golang/protobuf v1.3.2
	github.com/pelletier/go-toml v1.2.0
	github.com/shirou/gopsutil v2.18.13-0.20190301133041-6c6abd6d1666+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/sirupsen/logrus v1.4.2
	golang.org/x/net v0.0.0-20190324223953-e3b2ff56ed87
	golang.org/x/sys v0.0.0-20190422165155-953cdadca894
	golang.org/x/text v0.3.0
	google.golang.org/genproto v0.0.0-20190321212433-e79c0c59cdb5
	google.golang.org/grpc v1.24.0
)

replace (
	git.jba.io/go/gorram/certs => ../certs
	git.jba.io/go/gorram/checks => ../checks
	git.jba.io/go/gorram/proto => ../proto
)
