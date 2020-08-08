module git.jba.io/go/gorram

go 1.13

replace (
	git.jba.io/go/gorram/certs => ./certs
	git.jba.io/go/gorram/checks => ./checks
	git.jba.io/go/gorram/client => ./client
	git.jba.io/go/gorram/proto => ./proto
	git.jba.io/go/gorram/server => ./server
)

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/golang/protobuf v1.4.2
	github.com/gregdel/pushover v0.0.0-20200416074932-c8ad547caed4
	github.com/lib/pq v1.5.2
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.6.0
	github.com/tevjef/go-runtime-metrics v0.0.0-20170326170900-527a54029307
	golang.org/x/net v0.0.0-20200513185701-a91f0712d120
	golang.org/x/sys v0.0.0-20200515095857-1151b9dac4a9 // indirect
	golang.org/x/text v0.3.2 // indirect
	google.golang.org/genproto v0.0.0-20200515170657-fc4c6c6a6587 // indirect
	google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v2 v2.3.0
)
