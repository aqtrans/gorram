// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/gorram.proto

/*
Package gorram is a generated protocol buffer package.

It is generated from these files:
	proto/gorram.proto

It has these top-level messages:
	IsAlive
	Submitted
	Issue
	Config
	Deluge
	DiskSpace
	Load
	ProcessExists
	GetURL
	ConfigRequest
*/
package gorram

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type IsAlive struct {
	IsAlive     bool  `protobuf:"varint,1,opt,name=is_alive,json=isAlive" json:"is_alive,omitempty"`
	LastUpdated int64 `protobuf:"varint,2,opt,name=last_updated,json=lastUpdated" json:"last_updated,omitempty"`
}

func (m *IsAlive) Reset()                    { *m = IsAlive{} }
func (m *IsAlive) String() string            { return proto.CompactTextString(m) }
func (*IsAlive) ProtoMessage()               {}
func (*IsAlive) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *IsAlive) GetIsAlive() bool {
	if m != nil {
		return m.IsAlive
	}
	return false
}

func (m *IsAlive) GetLastUpdated() int64 {
	if m != nil {
		return m.LastUpdated
	}
	return 0
}

type Submitted struct {
	SuccessfullySubmitted bool `protobuf:"varint,1,opt,name=successfully_submitted,json=successfullySubmitted" json:"successfully_submitted,omitempty"`
}

func (m *Submitted) Reset()                    { *m = Submitted{} }
func (m *Submitted) String() string            { return proto.CompactTextString(m) }
func (*Submitted) ProtoMessage()               {}
func (*Submitted) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Submitted) GetSuccessfullySubmitted() bool {
	if m != nil {
		return m.SuccessfullySubmitted
	}
	return false
}

type Issue struct {
	Title string `protobuf:"bytes,1,opt,name=title" json:"title,omitempty"`
	// Message itself
	Message string `protobuf:"bytes,2,opt,name=message" json:"message,omitempty"`
	// When issue was sent
	TimeSubmitted int64 `protobuf:"varint,3,opt,name=time_submitted,json=timeSubmitted" json:"time_submitted,omitempty"`
}

func (m *Issue) Reset()                    { *m = Issue{} }
func (m *Issue) String() string            { return proto.CompactTextString(m) }
func (*Issue) ProtoMessage()               {}
func (*Issue) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Issue) GetTitle() string {
	if m != nil {
		return m.Title
	}
	return ""
}

func (m *Issue) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *Issue) GetTimeSubmitted() int64 {
	if m != nil {
		return m.TimeSubmitted
	}
	return 0
}

type Config struct {
	// Used internally to tell when
	LastUpdated int64 `protobuf:"varint,1,opt,name=last_updated,json=lastUpdated" json:"last_updated,omitempty"`
	Interval    int64 `protobuf:"varint,2,opt,name=interval" json:"interval,omitempty"`
	// Only allow one Deluge check per-host
	Deluge *Deluge `protobuf:"bytes,3,opt,name=deluge" json:"deluge,omitempty"`
	// Only one load check per-host
	Load *Load `protobuf:"bytes,4,opt,name=load" json:"load,omitempty"`
	// Allow multiple instances of other checks
	Disk   []*DiskSpace     `protobuf:"bytes,5,rep,name=disk" json:"disk,omitempty"`
	Ps     []*ProcessExists `protobuf:"bytes,6,rep,name=ps" json:"ps,omitempty"`
	GetUrl []*GetURL        `protobuf:"bytes,7,rep,name=get_url,json=getUrl" json:"get_url,omitempty"`
}

func (m *Config) Reset()                    { *m = Config{} }
func (m *Config) String() string            { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()               {}
func (*Config) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Config) GetLastUpdated() int64 {
	if m != nil {
		return m.LastUpdated
	}
	return 0
}

func (m *Config) GetInterval() int64 {
	if m != nil {
		return m.Interval
	}
	return 0
}

func (m *Config) GetDeluge() *Deluge {
	if m != nil {
		return m.Deluge
	}
	return nil
}

func (m *Config) GetLoad() *Load {
	if m != nil {
		return m.Load
	}
	return nil
}

func (m *Config) GetDisk() []*DiskSpace {
	if m != nil {
		return m.Disk
	}
	return nil
}

func (m *Config) GetPs() []*ProcessExists {
	if m != nil {
		return m.Ps
	}
	return nil
}

func (m *Config) GetGetUrl() []*GetURL {
	if m != nil {
		return m.GetUrl
	}
	return nil
}

type Deluge struct {
	Url         string `protobuf:"bytes,1,opt,name=url" json:"url,omitempty"`
	Password    string `protobuf:"bytes,2,opt,name=password" json:"password,omitempty"`
	MaxTorrents int64  `protobuf:"varint,3,opt,name=max_torrents,json=maxTorrents" json:"max_torrents,omitempty"`
}

func (m *Deluge) Reset()                    { *m = Deluge{} }
func (m *Deluge) String() string            { return proto.CompactTextString(m) }
func (*Deluge) ProtoMessage()               {}
func (*Deluge) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Deluge) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *Deluge) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *Deluge) GetMaxTorrents() int64 {
	if m != nil {
		return m.MaxTorrents
	}
	return 0
}

type DiskSpace struct {
	Partition string  `protobuf:"bytes,1,opt,name=partition" json:"partition,omitempty"`
	MaxUsage  float64 `protobuf:"fixed64,2,opt,name=max_usage,json=maxUsage" json:"max_usage,omitempty"`
}

func (m *DiskSpace) Reset()                    { *m = DiskSpace{} }
func (m *DiskSpace) String() string            { return proto.CompactTextString(m) }
func (*DiskSpace) ProtoMessage()               {}
func (*DiskSpace) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *DiskSpace) GetPartition() string {
	if m != nil {
		return m.Partition
	}
	return ""
}

func (m *DiskSpace) GetMaxUsage() float64 {
	if m != nil {
		return m.MaxUsage
	}
	return 0
}

type Load struct {
	MaxLoad float64 `protobuf:"fixed64,1,opt,name=max_load,json=maxLoad" json:"max_load,omitempty"`
}

func (m *Load) Reset()                    { *m = Load{} }
func (m *Load) String() string            { return proto.CompactTextString(m) }
func (*Load) ProtoMessage()               {}
func (*Load) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *Load) GetMaxLoad() float64 {
	if m != nil {
		return m.MaxLoad
	}
	return 0
}

type ProcessExists struct {
	Path string `protobuf:"bytes,1,opt,name=path" json:"path,omitempty"`
	User string `protobuf:"bytes,2,opt,name=user" json:"user,omitempty"`
}

func (m *ProcessExists) Reset()                    { *m = ProcessExists{} }
func (m *ProcessExists) String() string            { return proto.CompactTextString(m) }
func (*ProcessExists) ProtoMessage()               {}
func (*ProcessExists) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *ProcessExists) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *ProcessExists) GetUser() string {
	if m != nil {
		return m.User
	}
	return ""
}

type GetURL struct {
	Url          string `protobuf:"bytes,1,opt,name=url" json:"url,omitempty"`
	ExpectedBody string `protobuf:"bytes,2,opt,name=expected_body,json=expectedBody" json:"expected_body,omitempty"`
}

func (m *GetURL) Reset()                    { *m = GetURL{} }
func (m *GetURL) String() string            { return proto.CompactTextString(m) }
func (*GetURL) ProtoMessage()               {}
func (*GetURL) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *GetURL) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *GetURL) GetExpectedBody() string {
	if m != nil {
		return m.ExpectedBody
	}
	return ""
}

type ConfigRequest struct {
	ClientName string `protobuf:"bytes,1,opt,name=client_name,json=clientName" json:"client_name,omitempty"`
}

func (m *ConfigRequest) Reset()                    { *m = ConfigRequest{} }
func (m *ConfigRequest) String() string            { return proto.CompactTextString(m) }
func (*ConfigRequest) ProtoMessage()               {}
func (*ConfigRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *ConfigRequest) GetClientName() string {
	if m != nil {
		return m.ClientName
	}
	return ""
}

func init() {
	proto.RegisterType((*IsAlive)(nil), "gorram.IsAlive")
	proto.RegisterType((*Submitted)(nil), "gorram.Submitted")
	proto.RegisterType((*Issue)(nil), "gorram.Issue")
	proto.RegisterType((*Config)(nil), "gorram.Config")
	proto.RegisterType((*Deluge)(nil), "gorram.Deluge")
	proto.RegisterType((*DiskSpace)(nil), "gorram.DiskSpace")
	proto.RegisterType((*Load)(nil), "gorram.Load")
	proto.RegisterType((*ProcessExists)(nil), "gorram.ProcessExists")
	proto.RegisterType((*GetURL)(nil), "gorram.GetURL")
	proto.RegisterType((*ConfigRequest)(nil), "gorram.ConfigRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Reporter service

type ReporterClient interface {
	Ping(ctx context.Context, in *IsAlive, opts ...grpc.CallOption) (*Config, error)
	RecordIssue(ctx context.Context, opts ...grpc.CallOption) (Reporter_RecordIssueClient, error)
	SendConfig(ctx context.Context, in *ConfigRequest, opts ...grpc.CallOption) (*Config, error)
}

type reporterClient struct {
	cc *grpc.ClientConn
}

func NewReporterClient(cc *grpc.ClientConn) ReporterClient {
	return &reporterClient{cc}
}

func (c *reporterClient) Ping(ctx context.Context, in *IsAlive, opts ...grpc.CallOption) (*Config, error) {
	out := new(Config)
	err := grpc.Invoke(ctx, "/gorram.Reporter/Ping", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *reporterClient) RecordIssue(ctx context.Context, opts ...grpc.CallOption) (Reporter_RecordIssueClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_Reporter_serviceDesc.Streams[0], c.cc, "/gorram.Reporter/RecordIssue", opts...)
	if err != nil {
		return nil, err
	}
	x := &reporterRecordIssueClient{stream}
	return x, nil
}

type Reporter_RecordIssueClient interface {
	Send(*Issue) error
	CloseAndRecv() (*Submitted, error)
	grpc.ClientStream
}

type reporterRecordIssueClient struct {
	grpc.ClientStream
}

func (x *reporterRecordIssueClient) Send(m *Issue) error {
	return x.ClientStream.SendMsg(m)
}

func (x *reporterRecordIssueClient) CloseAndRecv() (*Submitted, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(Submitted)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *reporterClient) SendConfig(ctx context.Context, in *ConfigRequest, opts ...grpc.CallOption) (*Config, error) {
	out := new(Config)
	err := grpc.Invoke(ctx, "/gorram.Reporter/SendConfig", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Reporter service

type ReporterServer interface {
	Ping(context.Context, *IsAlive) (*Config, error)
	RecordIssue(Reporter_RecordIssueServer) error
	SendConfig(context.Context, *ConfigRequest) (*Config, error)
}

func RegisterReporterServer(s *grpc.Server, srv ReporterServer) {
	s.RegisterService(&_Reporter_serviceDesc, srv)
}

func _Reporter_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IsAlive)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ReporterServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gorram.Reporter/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ReporterServer).Ping(ctx, req.(*IsAlive))
	}
	return interceptor(ctx, in, info, handler)
}

func _Reporter_RecordIssue_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ReporterServer).RecordIssue(&reporterRecordIssueServer{stream})
}

type Reporter_RecordIssueServer interface {
	SendAndClose(*Submitted) error
	Recv() (*Issue, error)
	grpc.ServerStream
}

type reporterRecordIssueServer struct {
	grpc.ServerStream
}

func (x *reporterRecordIssueServer) SendAndClose(m *Submitted) error {
	return x.ServerStream.SendMsg(m)
}

func (x *reporterRecordIssueServer) Recv() (*Issue, error) {
	m := new(Issue)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Reporter_SendConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ReporterServer).SendConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gorram.Reporter/SendConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ReporterServer).SendConfig(ctx, req.(*ConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Reporter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gorram.Reporter",
	HandlerType: (*ReporterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _Reporter_Ping_Handler,
		},
		{
			MethodName: "SendConfig",
			Handler:    _Reporter_SendConfig_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RecordIssue",
			Handler:       _Reporter_RecordIssue_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "proto/gorram.proto",
}

func init() { proto.RegisterFile("proto/gorram.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 594 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x54, 0xdd, 0x6e, 0xd4, 0x3c,
	0x10, 0x6d, 0x76, 0xb7, 0xd9, 0xdd, 0xd9, 0x6e, 0xbf, 0x0f, 0x8b, 0xa2, 0x50, 0x90, 0xd8, 0x06,
	0x15, 0x96, 0x9b, 0x82, 0x5a, 0x55, 0x5c, 0x22, 0xca, 0x4f, 0x55, 0xa9, 0x42, 0x95, 0xcb, 0x5e,
	0x70, 0x43, 0xe4, 0xae, 0xa7, 0xc1, 0x6a, 0x12, 0x07, 0xdb, 0x29, 0xe9, 0x1b, 0xf0, 0x1a, 0xbc,
	0x29, 0xb2, 0xe3, 0x64, 0x5b, 0x95, 0x3b, 0xcf, 0x99, 0xe3, 0x99, 0x33, 0xc7, 0x93, 0x00, 0x29,
	0x95, 0x34, 0xf2, 0x75, 0x2a, 0x95, 0x62, 0xf9, 0x9e, 0x0b, 0x48, 0xd8, 0x44, 0xf1, 0x31, 0x0c,
	0x4f, 0xf4, 0xfb, 0x4c, 0x5c, 0x23, 0x79, 0x0c, 0x23, 0xa1, 0x13, 0x66, 0xcf, 0x51, 0x30, 0x0b,
	0xe6, 0x23, 0x3a, 0x14, 0x3e, 0xb5, 0x03, 0x1b, 0x19, 0xd3, 0x26, 0xa9, 0x4a, 0xce, 0x0c, 0xf2,
	0xa8, 0x37, 0x0b, 0xe6, 0x7d, 0x3a, 0xb1, 0xd8, 0xa2, 0x81, 0xe2, 0x23, 0x18, 0x9f, 0x57, 0x17,
	0xb9, 0x30, 0x06, 0x39, 0x39, 0x84, 0x47, 0xba, 0x5a, 0x2e, 0x51, 0xeb, 0xcb, 0x2a, 0xcb, 0x6e,
	0x12, 0xdd, 0x66, 0x7c, 0xe1, 0xad, 0xdb, 0xd9, 0xee, 0x5a, 0xfc, 0x1d, 0xd6, 0x4f, 0xb4, 0xae,
	0x90, 0x3c, 0x84, 0x75, 0x23, 0x4c, 0xd6, 0xe8, 0x18, 0xd3, 0x26, 0x20, 0x11, 0x0c, 0x73, 0xd4,
	0x9a, 0xa5, 0xe8, 0x04, 0x8c, 0x69, 0x1b, 0x92, 0x5d, 0xd8, 0x34, 0x22, 0xc7, 0x5b, 0x7d, 0xfa,
	0x4e, 0xe1, 0xd4, 0xa2, 0xab, 0xfa, 0xbf, 0x7b, 0x10, 0x7e, 0x90, 0xc5, 0xa5, 0x48, 0xef, 0x4d,
	0x14, 0xdc, 0x9b, 0x88, 0x6c, 0xc3, 0x48, 0x14, 0x06, 0xd5, 0x35, 0xcb, 0xfc, 0xc0, 0x5d, 0x4c,
	0x5e, 0x40, 0xc8, 0x31, 0xab, 0x52, 0x74, 0x8d, 0x26, 0xfb, 0x9b, 0x7b, 0xde, 0xdd, 0x8f, 0x0e,
	0xa5, 0x3e, 0x4b, 0x66, 0x30, 0xc8, 0x24, 0xe3, 0xd1, 0xc0, 0xb1, 0x36, 0x5a, 0xd6, 0xa9, 0x64,
	0x9c, 0xba, 0x0c, 0xd9, 0x85, 0x01, 0x17, 0xfa, 0x2a, 0x5a, 0x9f, 0xf5, 0xe7, 0x93, 0xfd, 0x07,
	0x5d, 0x1d, 0xa1, 0xaf, 0xce, 0x4b, 0xb6, 0x44, 0xea, 0xd2, 0x64, 0x17, 0x7a, 0xa5, 0x8e, 0x42,
	0x47, 0xda, 0x6a, 0x49, 0x67, 0x4a, 0x5a, 0x17, 0x3f, 0xd5, 0x42, 0x1b, 0x4d, 0x7b, 0xa5, 0x26,
	0x2f, 0x61, 0x98, 0xa2, 0x49, 0x2a, 0x95, 0x45, 0x43, 0xc7, 0xed, 0x84, 0x1d, 0xa3, 0x59, 0xd0,
	0x53, 0x1a, 0xa6, 0x68, 0x16, 0x2a, 0x8b, 0xbf, 0x41, 0xd8, 0x48, 0x25, 0xff, 0x43, 0xdf, 0xd2,
	0x1b, 0xa7, 0xed, 0xd1, 0x0e, 0x5e, 0x32, 0xad, 0x7f, 0x49, 0xc5, 0xbd, 0xd1, 0x5d, 0x6c, 0x7d,
	0xcb, 0x59, 0x9d, 0x18, 0xa9, 0x14, 0x16, 0x46, 0x7b, 0x9f, 0x27, 0x39, 0xab, 0xbf, 0x7a, 0x28,
	0xfe, 0x0c, 0xe3, 0x4e, 0x3d, 0x79, 0x0a, 0xe3, 0x92, 0x29, 0x23, 0x8c, 0x90, 0x85, 0xef, 0xb1,
	0x02, 0xc8, 0x13, 0x18, 0xdb, 0x6a, 0x55, 0xf7, 0xa6, 0x01, 0x1d, 0xe5, 0xac, 0x5e, 0xd8, 0x38,
	0xde, 0x81, 0x81, 0xf5, 0xc9, 0xee, 0xa5, 0x25, 0x39, 0x1f, 0x03, 0xc7, 0x19, 0xe6, 0xac, 0xb6,
	0xa9, 0xf8, 0x2d, 0x4c, 0xef, 0x78, 0x40, 0x08, 0x0c, 0x4a, 0x66, 0x7e, 0xf8, 0x4e, 0xee, 0x6c,
	0xb1, 0x4a, 0xa3, 0xf2, 0xa3, 0xb8, 0x73, 0xfc, 0x0e, 0xc2, 0xc6, 0x90, 0x7f, 0x8c, 0xff, 0x1c,
	0xa6, 0x58, 0x97, 0xb8, 0x34, 0xc8, 0x93, 0x0b, 0xc9, 0x6f, 0xfc, 0xc5, 0x8d, 0x16, 0x3c, 0x92,
	0xfc, 0x26, 0x7e, 0x03, 0xd3, 0x66, 0x93, 0x28, 0xfe, 0xac, 0x50, 0x1b, 0xf2, 0x0c, 0x26, 0xcb,
	0x4c, 0x60, 0x61, 0x92, 0x82, 0xe5, 0xed, 0xe2, 0x42, 0x03, 0x7d, 0x61, 0x39, 0xee, 0xff, 0x09,
	0x60, 0x44, 0xb1, 0x94, 0xca, 0xa0, 0x22, 0xaf, 0x60, 0x70, 0x26, 0x8a, 0x94, 0xfc, 0xd7, 0x3e,
	0x8f, 0xff, 0x08, 0xb7, 0xbb, 0xf7, 0x6a, 0xaa, 0xc7, 0x6b, 0xe4, 0x00, 0x26, 0x14, 0x97, 0x52,
	0xf1, 0xe6, 0xd3, 0x98, 0xae, 0x6e, 0xe8, 0x0a, 0xb7, 0xbb, 0x85, 0x59, 0x6d, 0xf9, 0xda, 0x3c,
	0x20, 0x87, 0x00, 0xe7, 0x58, 0x70, 0xbf, 0xec, 0x5b, 0x77, 0x8b, 0x7a, 0xc9, 0xf7, 0x7b, 0x5d,
	0x84, 0xee, 0xe7, 0x70, 0xf0, 0x37, 0x00, 0x00, 0xff, 0xff, 0xb0, 0x8e, 0xd4, 0x28, 0x32, 0x04,
	0x00, 0x00,
}
