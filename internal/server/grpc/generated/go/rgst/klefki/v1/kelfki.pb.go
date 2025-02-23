// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        (unknown)
// source: rgst/klefki/v1/kelfki.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/gofeaturespb"
	reflect "reflect"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetKeyRequest struct {
	state         protoimpl.MessageState `protogen:"opaque.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetKeyRequest) Reset() {
	*x = GetKeyRequest{}
	mi := &file_rgst_klefki_v1_kelfki_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetKeyRequest) ProtoMessage() {}

func (x *GetKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rgst_klefki_v1_kelfki_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

type GetKeyRequest_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

}

func (b0 GetKeyRequest_builder) Build() *GetKeyRequest {
	m0 := &GetKeyRequest{}
	b, x := &b0, m0
	_, _ = b, x
	return m0
}

type GetKeyResponse struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Key         *string                `protobuf:"bytes,1,opt,name=key"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *GetKeyResponse) Reset() {
	*x = GetKeyResponse{}
	mi := &file_rgst_klefki_v1_kelfki_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetKeyResponse) ProtoMessage() {}

func (x *GetKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rgst_klefki_v1_kelfki_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *GetKeyResponse) GetKey() string {
	if x != nil {
		if x.xxx_hidden_Key != nil {
			return *x.xxx_hidden_Key
		}
		return ""
	}
	return ""
}

func (x *GetKeyResponse) SetKey(v string) {
	x.xxx_hidden_Key = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 1)
}

func (x *GetKeyResponse) HasKey() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *GetKeyResponse) ClearKey() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Key = nil
}

type GetKeyResponse_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Key *string
}

func (b0 GetKeyResponse_builder) Build() *GetKeyResponse {
	m0 := &GetKeyResponse{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Key != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 1)
		x.xxx_hidden_Key = b.Key
	}
	return m0
}

var File_rgst_klefki_v1_kelfki_proto protoreflect.FileDescriptor

var file_rgst_klefki_v1_kelfki_proto_rawDesc = string([]byte{
	0x0a, 0x1b, 0x72, 0x67, 0x73, 0x74, 0x2f, 0x6b, 0x6c, 0x65, 0x66, 0x6b, 0x69, 0x2f, 0x76, 0x31,
	0x2f, 0x6b, 0x65, 0x6c, 0x66, 0x6b, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x72,
	0x67, 0x73, 0x74, 0x2e, 0x6b, 0x6c, 0x65, 0x66, 0x6b, 0x69, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x67,
	0x6f, 0x5f, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x0f, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x22, 0x22, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x32, 0x58, 0x0a, 0x0d, 0x4b, 0x6c, 0x65, 0x66, 0x6b, 0x69, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x47, 0x0a, 0x06, 0x47, 0x65, 0x74, 0x4b, 0x65, 0x79,
	0x12, 0x1d, 0x2e, 0x72, 0x67, 0x73, 0x74, 0x2e, 0x6b, 0x6c, 0x65, 0x66, 0x6b, 0x69, 0x2e, 0x76,
	0x31, 0x2e, 0x47, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1e, 0x2e, 0x72, 0x67, 0x73, 0x74, 0x2e, 0x6b, 0x6c, 0x65, 0x66, 0x6b, 0x69, 0x2e, 0x76, 0x31,
	0x2e, 0x47, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42,
	0x3f, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x2e, 0x72, 0x67, 0x73, 0x74, 0x2e, 0x69, 0x6f, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x67, 0x65, 0x6e,
	0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x67, 0x6f, 0x2f, 0x72, 0x67, 0x73, 0x74, 0x2f, 0x6b,
	0x6c, 0x65, 0x66, 0x6b, 0x69, 0x2f, 0x76, 0x31, 0x92, 0x03, 0x05, 0xd2, 0x3e, 0x02, 0x10, 0x03,
	0x62, 0x08, 0x65, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x70, 0xe8, 0x07,
})

var file_rgst_klefki_v1_kelfki_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_rgst_klefki_v1_kelfki_proto_goTypes = []any{
	(*GetKeyRequest)(nil),  // 0: rgst.klefki.v1.GetKeyRequest
	(*GetKeyResponse)(nil), // 1: rgst.klefki.v1.GetKeyResponse
}
var file_rgst_klefki_v1_kelfki_proto_depIdxs = []int32{
	0, // 0: rgst.klefki.v1.KlefkiService.GetKey:input_type -> rgst.klefki.v1.GetKeyRequest
	1, // 1: rgst.klefki.v1.KlefkiService.GetKey:output_type -> rgst.klefki.v1.GetKeyResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_rgst_klefki_v1_kelfki_proto_init() }
func file_rgst_klefki_v1_kelfki_proto_init() {
	if File_rgst_klefki_v1_kelfki_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_rgst_klefki_v1_kelfki_proto_rawDesc), len(file_rgst_klefki_v1_kelfki_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rgst_klefki_v1_kelfki_proto_goTypes,
		DependencyIndexes: file_rgst_klefki_v1_kelfki_proto_depIdxs,
		MessageInfos:      file_rgst_klefki_v1_kelfki_proto_msgTypes,
	}.Build()
	File_rgst_klefki_v1_kelfki_proto = out.File
	file_rgst_klefki_v1_kelfki_proto_goTypes = nil
	file_rgst_klefki_v1_kelfki_proto_depIdxs = nil
}
