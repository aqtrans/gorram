// Code generated by protoc-gen-go. DO NOT EDIT.
// source: gorram.proto

/*
Package gorram is a generated protocol buffer package.

It is generated from these files:
	gorram.proto

It has these top-level messages:
	PingMessage
	Submitted
	Issue
*/
package gorram

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/timestamp"

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
	ClientName string `protobuf:"bytes,1,opt,name=client_name,json=clientName" json:"client_name,omitempty"`
	IsAlive    bool   `protobuf:"varint,2,opt,name=is_alive,json=isAlive" json:"is_alive,omitempty"`
}

func (m *PingMessage) Reset()                    { *m = PingMessage{} }
func (m *PingMessage) String() string            { return proto.CompactTextString(m) }
func (*PingMessage) ProtoMessage()               {}
func (*PingMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *PingMessage) GetClientName() string {
	if m != nil {
		return m.ClientName
	}
	return ""
}

func (m *PingMessage) GetIsAlive() bool {
	if m != nil {
		return m.IsAlive
	}
	return false
}

type Submitted struct {
	SuccessfullySubmitted bool `protobuf:"varint,2,opt,name=successfully_submitted,json=successfullySubmitted" json:"successfully_submitted,omitempty"`
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
	// Name of the client submitting the issue
	ClientName string `protobuf:"bytes,1,opt,name=client_name,json=clientName" json:"client_name,omitempty"`
	// Message itself
	Message string `protobuf:"bytes,2,opt,name=message" json:"message,omitempty"`
	// When issue was sent
	TimeSubmitted *google_protobuf.Timestamp `protobuf:"bytes,3,opt,name=time_submitted,json=timeSubmitted" json:"time_submitted,omitempty"`
}

func (m *Issue) Reset()                    { *m = Issue{} }
func (m *Issue) String() string            { return proto.CompactTextString(m) }
func (*Issue) ProtoMessage()               {}
func (*Issue) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Issue) GetClientName() string {
	if m != nil {
		return m.ClientName
	}
	return ""
}

func (m *Issue) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *Issue) GetTimeSubmitted() *google_protobuf.Timestamp {
	if m != nil {
		return m.TimeSubmitted
	}
	return nil
}

func init() {
	proto.RegisterType((*PingMessage)(nil), "gorram.PingMessage")
	proto.RegisterType((*Submitted)(nil), "gorram.Submitted")
	proto.RegisterType((*Issue)(nil), "gorram.Issue")
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
	RecordIssue(ctx context.Context, opts ...grpc.CallOption) (Reporter_RecordIssueClient, error)
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

// Server API for Reporter service

type ReporterServer interface {
	Ping(context.Context, *PingMessage) (*PingMessage, error)
	RecordIssue(Reporter_RecordIssueServer) error
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

var _Reporter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gorram.Reporter",
	HandlerType: (*ReporterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _Reporter_Ping_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RecordIssue",
			Handler:       _Reporter_RecordIssue_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "gorram.proto",
}

func init() { proto.RegisterFile("gorram.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 284 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0xcf, 0x4e, 0xf3, 0x30,
	0x10, 0xc4, 0xeb, 0xef, 0x83, 0xfe, 0xd9, 0x50, 0x24, 0x8c, 0x40, 0x25, 0x97, 0x56, 0x39, 0xe5,
	0x94, 0x4a, 0xad, 0x78, 0x80, 0x72, 0xeb, 0x01, 0x84, 0x0c, 0xf7, 0xca, 0x4d, 0xb7, 0x91, 0xa5,
	0x38, 0x8e, 0xbc, 0x0e, 0x12, 0x0f, 0xc0, 0x7b, 0xa3, 0xc4, 0x75, 0xc9, 0x81, 0x03, 0xc7, 0xd9,
	0xdd, 0xb1, 0x67, 0x7e, 0x70, 0x55, 0x18, 0x6b, 0xa5, 0xce, 0x6a, 0x6b, 0x9c, 0xe1, 0x43, 0xaf,
	0xe2, 0x79, 0x61, 0x4c, 0x51, 0xe2, 0xb2, 0x9b, 0xee, 0x9b, 0xe3, 0xd2, 0x29, 0x8d, 0xe4, 0xa4,
	0xae, 0xfd, 0x61, 0xb2, 0x85, 0xe8, 0x55, 0x55, 0xc5, 0x33, 0x12, 0xc9, 0x02, 0xf9, 0x1c, 0xa2,
	0xbc, 0x54, 0x58, 0xb9, 0x5d, 0x25, 0x35, 0xce, 0xd8, 0x82, 0xa5, 0x13, 0x01, 0x7e, 0xf4, 0x22,
	0x35, 0xf2, 0x07, 0x18, 0x2b, 0xda, 0xc9, 0x52, 0x7d, 0xe0, 0xec, 0xdf, 0x82, 0xa5, 0x63, 0x31,
	0x52, 0xb4, 0x69, 0x65, 0xf2, 0x04, 0x93, 0xb7, 0x66, 0xaf, 0x95, 0x73, 0x78, 0xe0, 0x8f, 0x70,
	0x4f, 0x4d, 0x9e, 0x23, 0xd1, 0xb1, 0x29, 0xcb, 0xcf, 0x1d, 0x85, 0xcd, 0xc9, 0x75, 0xd7, 0xdf,
	0x9e, 0x6d, 0xc9, 0x17, 0x83, 0xcb, 0x2d, 0x51, 0xf3, 0x87, 0x24, 0x33, 0x18, 0x69, 0x9f, 0xba,
	0x7b, 0x72, 0x22, 0x82, 0xe4, 0x1b, 0xb8, 0x6e, 0x6b, 0xf6, 0xfe, 0xfc, 0xbf, 0x60, 0x69, 0xb4,
	0x8a, 0x33, 0x4f, 0x23, 0x0b, 0x34, 0xb2, 0xf7, 0x40, 0x43, 0x4c, 0x5b, 0xc7, 0x39, 0xc7, 0x8a,
	0x60, 0x2c, 0xb0, 0x36, 0xd6, 0xa1, 0xe5, 0x2b, 0xb8, 0x68, 0x11, 0xf1, 0xdb, 0xec, 0x84, 0xb8,
	0x07, 0x2c, 0xfe, 0x6d, 0x98, 0x0c, 0xf8, 0x1a, 0x22, 0x81, 0xb9, 0xb1, 0x07, 0x5f, 0x66, 0x1a,
	0xae, 0x3a, 0x19, 0xdf, 0x04, 0xf9, 0x53, 0x7c, 0x90, 0xb2, 0xfd, 0xb0, 0xcb, 0xb5, 0xfe, 0x0e,
	0x00, 0x00, 0xff, 0xff, 0x0b, 0xac, 0x78, 0x77, 0xcb, 0x01, 0x00, 0x00,
}
