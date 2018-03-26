// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/gorram.proto

/*
Package gorram is a generated protocol buffer package.

It is generated from these files:
	proto/gorram.proto

It has these top-level messages:
	PingMessage
	Submitted
	Issue
	Config
	Parsed
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

type PingMessage struct {
	IsAlive bool `protobuf:"varint,1,opt,name=is_alive,json=isAlive" json:"is_alive,omitempty"`
}

func (m *PingMessage) Reset()                    { *m = PingMessage{} }
func (m *PingMessage) String() string            { return proto.CompactTextString(m) }
func (*PingMessage) ProtoMessage()               {}
func (*PingMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *PingMessage) GetIsAlive() bool {
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
	// Message itself
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
	// When issue was sent
	TimeSubmitted int64 `protobuf:"varint,2,opt,name=time_submitted,json=timeSubmitted" json:"time_submitted,omitempty"`
}

func (m *Issue) Reset()                    { *m = Issue{} }
func (m *Issue) String() string            { return proto.CompactTextString(m) }
func (*Issue) ProtoMessage()               {}
func (*Issue) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

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
	// Raw config file
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

type Parsed struct {
	CfgParsed bool `protobuf:"varint,1,opt,name=cfg_parsed,json=cfgParsed" json:"cfg_parsed,omitempty"`
}

func (m *Parsed) Reset()                    { *m = Parsed{} }
func (m *Parsed) String() string            { return proto.CompactTextString(m) }
func (*Parsed) ProtoMessage()               {}
func (*Parsed) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Parsed) GetCfgParsed() bool {
	if m != nil {
		return m.CfgParsed
	}
	return false
}

func init() {
	proto.RegisterType((*PingMessage)(nil), "gorram.PingMessage")
	proto.RegisterType((*Submitted)(nil), "gorram.Submitted")
	proto.RegisterType((*Issue)(nil), "gorram.Issue")
	proto.RegisterType((*Config)(nil), "gorram.Config")
	proto.RegisterType((*Parsed)(nil), "gorram.Parsed")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Reporter service

type ReporterClient interface {
	Ping(ctx context.Context, in *PingMessage, opts ...grpc.CallOption) (*PingMessage, error)
	RecordIssue(ctx context.Context, in *Issue, opts ...grpc.CallOption) (*Submitted, error)
	SendConfig(ctx context.Context, in *Config, opts ...grpc.CallOption) (*Parsed, error)
}

type reporterClient struct {
	cc *grpc.ClientConn
}

func NewReporterClient(cc *grpc.ClientConn) ReporterClient {
	return &reporterClient{cc}
}

func (c *reporterClient) Ping(ctx context.Context, in *PingMessage, opts ...grpc.CallOption) (*PingMessage, error) {
	out := new(PingMessage)
	err := grpc.Invoke(ctx, "/gorram.Reporter/Ping", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *reporterClient) RecordIssue(ctx context.Context, in *Issue, opts ...grpc.CallOption) (*Submitted, error) {
	out := new(Submitted)
	err := grpc.Invoke(ctx, "/gorram.Reporter/RecordIssue", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *reporterClient) SendConfig(ctx context.Context, in *Config, opts ...grpc.CallOption) (*Parsed, error) {
	out := new(Parsed)
	err := grpc.Invoke(ctx, "/gorram.Reporter/SendConfig", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Reporter service

type ReporterServer interface {
	Ping(context.Context, *PingMessage) (*PingMessage, error)
	RecordIssue(context.Context, *Issue) (*Submitted, error)
	SendConfig(context.Context, *Config) (*Parsed, error)
}

func RegisterReporterServer(s *grpc.Server, srv ReporterServer) {
	s.RegisterService(&_Reporter_serviceDesc, srv)
}

func _Reporter_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PingMessage)
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
		return srv.(ReporterServer).Ping(ctx, req.(*PingMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Reporter_RecordIssue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Issue)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ReporterServer).RecordIssue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gorram.Reporter/RecordIssue",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ReporterServer).RecordIssue(ctx, req.(*Issue))
	}
	return interceptor(ctx, in, info, handler)
}

func _Reporter_SendConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Config)
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
		return srv.(ReporterServer).SendConfig(ctx, req.(*Config))
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
			MethodName: "RecordIssue",
			Handler:    _Reporter_RecordIssue_Handler,
		},
		{
			MethodName: "SendConfig",
			Handler:    _Reporter_SendConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/gorram.proto",
}

func init() { proto.RegisterFile("proto/gorram.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 288 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x91, 0xdf, 0x4a, 0xc3, 0x30,
	0x14, 0xc6, 0x57, 0xa7, 0xdd, 0x76, 0xe6, 0x86, 0x1e, 0x51, 0x66, 0x41, 0x18, 0x01, 0x71, 0x57,
	0x13, 0x27, 0x3e, 0x80, 0x7a, 0xa3, 0x17, 0xc2, 0xc8, 0x1e, 0x60, 0x74, 0xe9, 0x69, 0x08, 0xac,
	0x4d, 0x49, 0x5a, 0xc1, 0xc7, 0xf1, 0x4d, 0xa5, 0x49, 0xbb, 0xf5, 0xc2, 0xbb, 0xfc, 0xce, 0x9f,
	0x2f, 0x5f, 0xbe, 0x00, 0x16, 0x46, 0x97, 0xfa, 0x51, 0x6a, 0x63, 0xe2, 0x6c, 0xe9, 0x00, 0x43,
	0x4f, 0x6c, 0x01, 0xe3, 0xb5, 0xca, 0xe5, 0x17, 0x59, 0x1b, 0x4b, 0xc2, 0x5b, 0x18, 0x2a, 0xbb,
	0x8d, 0xf7, 0xea, 0x9b, 0x66, 0xc1, 0x3c, 0x58, 0x0c, 0xf9, 0x40, 0xd9, 0xd7, 0x1a, 0xd9, 0x1b,
	0x8c, 0x36, 0xd5, 0x2e, 0x53, 0x65, 0x49, 0x09, 0xbe, 0xc0, 0x8d, 0xad, 0x84, 0x20, 0x6b, 0xd3,
	0x6a, 0xbf, 0xff, 0xd9, 0xda, 0xb6, 0xd3, 0x6c, 0x5d, 0x77, 0xbb, 0x87, 0x35, 0xf6, 0x01, 0x67,
	0x9f, 0xd6, 0x56, 0x84, 0x33, 0x18, 0x64, 0xfe, 0x4a, 0xb7, 0x30, 0xe2, 0x2d, 0xe2, 0x3d, 0x4c,
	0x4b, 0x95, 0x51, 0x47, 0xf1, 0x64, 0x1e, 0x2c, 0xfa, 0x7c, 0x52, 0x57, 0x8f, 0x4a, 0x11, 0x84,
	0xef, 0x3a, 0x4f, 0x95, 0xc4, 0x0b, 0xe8, 0x8b, 0x54, 0x3a, 0x99, 0x73, 0x5e, 0x1f, 0xd9, 0x03,
	0x84, 0xeb, 0xd8, 0x58, 0x4a, 0xf0, 0x0e, 0x40, 0xa4, 0x72, 0x5b, 0x38, 0x6a, 0xac, 0x8d, 0x44,
	0x2a, 0x7d, 0x7b, 0xf5, 0x1b, 0xc0, 0x90, 0x53, 0xa1, 0x4d, 0x49, 0x06, 0x57, 0x70, 0x5a, 0x27,
	0x81, 0x57, 0xcb, 0x26, 0xa8, 0x4e, 0x2e, 0xd1, 0x7f, 0x45, 0xd6, 0xc3, 0x27, 0x18, 0x73, 0x12,
	0xda, 0x24, 0xfe, 0x55, 0x93, 0x76, 0xca, 0x61, 0x74, 0xd9, 0xe2, 0xd1, 0x76, 0x0f, 0x97, 0x00,
	0x1b, 0xca, 0x93, 0xc6, 0xfc, 0xb4, 0x1d, 0xf1, 0x1c, 0x1d, 0xd8, 0x3b, 0x64, 0xbd, 0x5d, 0xe8,
	0xfe, 0xeb, 0xf9, 0x2f, 0x00, 0x00, 0xff, 0xff, 0xa4, 0x0b, 0x3d, 0x94, 0xc5, 0x01, 0x00, 0x00,
}
