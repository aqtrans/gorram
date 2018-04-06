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
	IsAlive bool `protobuf:"varint,1,opt,name=is_alive,json=isAlive" json:"is_alive,omitempty"`
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
	// Raw gob-encoded config file
	// Passing via gob/bytes so the checks/ libs hold the structs
	Cfg []byte `protobuf:"bytes,1,opt,name=cfg,proto3" json:"cfg,omitempty"`
}

func (m *Config) Reset()                    { *m = Config{} }
func (m *Config) String() string            { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()               {}
func (*Config) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Config) GetCfg() []byte {
	if m != nil {
		return m.Cfg
	}
	return nil
}

type ConfigRequest struct {
	ClientName string `protobuf:"bytes,1,opt,name=client_name,json=clientName" json:"client_name,omitempty"`
	CfgSha1Sum string `protobuf:"bytes,2,opt,name=cfg_sha1sum,json=cfgSha1sum" json:"cfg_sha1sum,omitempty"`
}

func (m *ConfigRequest) Reset()                    { *m = ConfigRequest{} }
func (m *ConfigRequest) String() string            { return proto.CompactTextString(m) }
func (*ConfigRequest) ProtoMessage()               {}
func (*ConfigRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *ConfigRequest) GetClientName() string {
	if m != nil {
		return m.ClientName
	}
	return ""
}

func (m *ConfigRequest) GetCfgSha1Sum() string {
	if m != nil {
		return m.CfgSha1Sum
	}
	return ""
}

func init() {
	proto.RegisterType((*IsAlive)(nil), "gorram.IsAlive")
	proto.RegisterType((*Submitted)(nil), "gorram.Submitted")
	proto.RegisterType((*Issue)(nil), "gorram.Issue")
	proto.RegisterType((*Config)(nil), "gorram.Config")
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
	Ping(ctx context.Context, in *IsAlive, opts ...grpc.CallOption) (*IsAlive, error)
	RecordIssue(ctx context.Context, opts ...grpc.CallOption) (Reporter_RecordIssueClient, error)
	SendConfig(ctx context.Context, in *ConfigRequest, opts ...grpc.CallOption) (*Config, error)
}

type reporterClient struct {
	cc *grpc.ClientConn
}

func NewReporterClient(cc *grpc.ClientConn) ReporterClient {
	return &reporterClient{cc}
}

func (c *reporterClient) Ping(ctx context.Context, in *IsAlive, opts ...grpc.CallOption) (*IsAlive, error) {
	out := new(IsAlive)
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
	Ping(context.Context, *IsAlive) (*IsAlive, error)
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
	// 321 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x91, 0xcd, 0x4e, 0xea, 0x40,
	0x14, 0xc7, 0xe9, 0xe5, 0xf2, 0x75, 0xb8, 0x70, 0xef, 0x3d, 0x11, 0x83, 0xdd, 0x48, 0x1a, 0x4d,
	0x88, 0x0b, 0x8c, 0x12, 0x1e, 0x40, 0x5d, 0xb1, 0x31, 0x3a, 0xec, 0x6d, 0x4a, 0x39, 0x1d, 0x27,
	0xe9, 0xb4, 0xd8, 0x33, 0x63, 0xe2, 0xeb, 0xf8, 0xa4, 0x86, 0x4e, 0x2b, 0xe0, 0x6e, 0xfe, 0xbf,
	0xff, 0xf9, 0x1e, 0xc0, 0x6d, 0x91, 0x9b, 0xfc, 0x5a, 0xe6, 0x45, 0x11, 0xe9, 0x59, 0x29, 0xb0,
	0xed, 0x54, 0x70, 0x01, 0x9d, 0x25, 0xdf, 0xa5, 0xea, 0x9d, 0xf0, 0x0c, 0xba, 0x8a, 0xc3, 0x68,
	0xf7, 0x1e, 0x7b, 0x13, 0x6f, 0xda, 0x15, 0x1d, 0xe5, 0xac, 0xe0, 0x1e, 0x7a, 0x2b, 0xbb, 0xd6,
	0xca, 0x18, 0xda, 0xe0, 0x02, 0x4e, 0xd9, 0xc6, 0x31, 0x31, 0x27, 0x36, 0x4d, 0x3f, 0x42, 0xae,
	0x9d, 0x2a, 0x6b, 0x74, 0xe8, 0x7e, 0xa7, 0x05, 0x2f, 0xd0, 0x5a, 0x32, 0x5b, 0xc2, 0x13, 0x68,
	0x19, 0x65, 0x52, 0xd7, 0xa4, 0x27, 0x9c, 0xc0, 0x31, 0x74, 0x34, 0x31, 0x47, 0x92, 0xc6, 0xbf,
	0x4a, 0x5e, 0x4b, 0xbc, 0x84, 0xa1, 0x51, 0x9a, 0x0e, 0xfa, 0x34, 0x27, 0xde, 0xb4, 0x29, 0x06,
	0x3b, 0xba, 0xaf, 0xef, 0x43, 0xfb, 0x21, 0xcf, 0x12, 0x25, 0xf1, 0x1f, 0x34, 0xe3, 0x44, 0x96,
	0xe5, 0xff, 0x88, 0xdd, 0x33, 0x78, 0x86, 0x81, 0xf3, 0x04, 0xbd, 0x59, 0x62, 0x83, 0xe7, 0xd0,
	0x8f, 0x53, 0x45, 0x99, 0x09, 0xb3, 0x48, 0xd7, 0x93, 0x80, 0x43, 0x8f, 0x91, 0xa6, 0x32, 0x20,
	0x91, 0x21, 0xbf, 0x46, 0x37, 0x6c, 0x75, 0x35, 0x12, 0xc4, 0x89, 0x5c, 0x39, 0x72, 0xfb, 0xe9,
	0x41, 0x57, 0xd0, 0x36, 0x2f, 0x0c, 0x15, 0x78, 0x05, 0xbf, 0x9f, 0x54, 0x26, 0xf1, 0xef, 0xac,
	0x3a, 0x72, 0x75, 0x53, 0xff, 0x27, 0x08, 0x1a, 0x38, 0x87, 0xbe, 0xa0, 0x38, 0x2f, 0x36, 0xee,
	0x1a, 0x83, 0x7d, 0x04, 0x5b, 0xf2, 0xff, 0xd7, 0x72, 0xbf, 0x58, 0x63, 0xea, 0xe1, 0x02, 0x60,
	0x45, 0xd9, 0xa6, 0x5a, 0x70, 0x54, 0x07, 0x1d, 0x2d, 0xe5, 0x0f, 0x8f, 0x71, 0xd0, 0x58, 0xb7,
	0xcb, 0xcf, 0x9e, 0x7f, 0x05, 0x00, 0x00, 0xff, 0xff, 0x19, 0x9e, 0xb4, 0xd1, 0x02, 0x02, 0x00,
	0x00,
}
