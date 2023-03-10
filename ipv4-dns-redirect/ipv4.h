/*
 * Copyright (C) 2023 The Windows Packet Filter Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include "winpfilter.h"

#pragma pack (1)

typedef struct _IPV4_ADDRESS {
	union 
	{
		ULONG	AddressInt32;
		BYTE	AddressBytes[4];
	};
}IPV4_ADDRESS,PIPV4_ADDRESS;
#define IPV4_ADDRESS_BYTE_LENGTH 4
#define IPV4_ADDRESS_BIT_LENGTH 32
typedef struct _IPV4_HEADER {
#if  BIG_ENDIAN
	BYTE	Version : 4;
	BYTE	HeaderLength : 4;
#else 
	BYTE	HeaderLength : 4;
	BYTE	Version : 4;
#endif
	BYTE	TOS;
	USHORT	TotalLength;
	USHORT	Identification;
#if  BIG_ENDIAN
	BYTE : 1;
	BYTE	DF : 1;
	BYTE	MF : 1;
	BYTE	OffsetH : 5;
#else
	BYTE	OffsetH : 5;
	BYTE	MF : 1;
	BYTE	DF : 1;
	BYTE : 1;
#endif
	BYTE	OffsetL;
	BYTE	TTL;
	BYTE	Protocol;
	USHORT	Checksum;
	IPV4_ADDRESS	SrcAddress;
	IPV4_ADDRESS	DestAddress;
}IPV4_HEADER, * PIPV4_HEADER;

#pragma pack ()

#define IPV4_HEADER_LENGTH(header)							((header)->HeaderLength)
#define IPV4_HEADER_LENGTH_BYTES(header)					(IPV4_HEADER_LENGTH(header)<<2)
#define IPV4_HEADER_TOS(header)								((header)->TOS)
#define IPV4_HEADER_TOTAL_LENGTH(header)					(CONVERT_NETE_16((header)->TotalLength))
#define IPV4_HEADER_ID(header)								(CONVERT_NETE_16((header)->Identification))
#define IPV4_HEADER_DF(header)								((header)->DF)
#define IPV4_HEADER_MF(header)								((header)->MF)
#define IPV4_HEADER_OFFSET(header)							((((header)->OffsetH) << 8) | ((header)->OffsetL))
#define IPV4_HEADER_TTL(header)								((header)->TTL)
#define IPV4_HEADER_PROTOCOL(header)						((header)->Protocol)
#define IPV4_HEADER_CHECKSUM(header)						(CONVERT_NETE_16((header)->Checksum))
#define IPV4_HEADER_SRC_ADDR(header)						(CONVERT_NETE_32((header)->SrcAddress.AddressInt32))
#define IPV4_HEADER_DEST_ADDR(header)						(CONVERT_NETE_32((header)->DestAddress.AddressInt32))

#define SET_IPV4_HEADER_LENGTH(header,length)				((header)->HeaderLength = (BYTE)length)
#define SET_IPV4_HEADER_LENGTH_BYTES(header,length_byte)	(SET_IPV4_HEADER_LENGTH(header,length_byte>>2))
#define SET_IPV4_HEADER_TOS(header,tos)						((header)->TOS = (BYTE)tos)
#define SET_IPV4_HEADER_TOTAL_LENGTH(header,total_length)	((header)->TotalLength = CONVERT_NETE_16(total_length))
#define SET_IPV4_HEADER_ID(header,id)						((header)->Identification = CONVERT_NETE_16(id))
#define SET_IPV4_HEADER_DF(header,df)						((header)->DF = (BYTE)df)
#define SET_IPV4_HEADER_MF(header,mf)						((header)->MF = (BYTE)mf)
#define SET_IPV4_HEADER_OFFSET(header,offset)				((header)->OffsetL=(((USHORT)offset)&0xff));((header)->OffsetH=((((USHORT)offset)>>8)&0x1f))
#define SET_IPV4_HEADER_TTL(header,ttl)						((header)->TTL = (BYTE)ttl)
#define SET_IPV4_HEADER_PROTOCOL(header,protocol)			((header)->Protocol = protocol)
#define SET_IPV4_HEADER_CHECKSUM(header,checksum)			((header)->Checksum = CONVERT_NETE_16(checksum))
#define SET_IPV4_HEADER_SRC_ADDR(header,src_addr)			((header)->SrcAddress.AddressInt32 = CONVERT_NETE_32(src_addr))
#define SET_IPV4_HEADER_DEST_ADDR(header,dest_addr)			((header)->DestAddress.AddressInt32 = CONVERT_NETE_32(dest_addr))

#define GetTransportLayerHeaderFromIPv4Header(header)		((BYTE*)(((BYTE*)header) + IPV4_HEADER_LENGTH_BYTES(header)))