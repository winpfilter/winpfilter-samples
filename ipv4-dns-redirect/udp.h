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
#include "converter.h"

#pragma pack (1)
typedef struct _UDP_HEADER {
	USHORT	SrcPort;
	USHORT  DestPort;
	USHORT	Length;
	USHORT	Checksum;
}UDP_HEADER,*PUDP_HEADER;
#pragma pack ()

#define UDP_HEADER_SRC_PORT(header)						(CONVERT_NETE_16((header)->SrcPort))
#define UDP_HEADER_DEST_PORT(header)					(CONVERT_NETE_16((header)->DestPort))
#define UDP_HEADER_LENGTH(header)						(CONVERT_NETE_16((header)->Length))
#define UDP_HEADER_CHECKSUM(header)						(CONVERT_NETE_16((header)->Checksum))

#define SET_UDP_HEADER_SRC_PORT(header,sport)			((header)->SrcPort = CONVERT_NETE_16(sport))
#define SET_UDP_HEADER_DEST_PORT(header,dport)			((header)->DestPort = CONVERT_NETE_16(dport))
#define SET_UDP_HEADER_LENGTH(header,length)			((header)->Length = CONVERT_NETE_16(length))
#define SET_UDP_HEADER_CHECKSUM(header,checksum)		((header)->Checksum = CONVERT_NETE_16(checksum))