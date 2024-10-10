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
}UDP_HEADER, * PUDP_HEADER;
#pragma pack ()

inline USHORT GetUDPHeaderSrcPort(PUDP_HEADER header) {
	return CONVERT_NETE_16(header->SrcPort);
}

inline VOID SetUDPHeaderSrcPort(PUDP_HEADER header, USHORT sport) {
	header->SrcPort = CONVERT_NETE_16(sport);
}


inline USHORT GetUDPHeaderDestPort(PUDP_HEADER header) {
	return CONVERT_NETE_16(header->DestPort);
}

inline VOID SetUDPHeaderDestPort(PUDP_HEADER header, USHORT dport) {
	header->DestPort = CONVERT_NETE_16(dport);
}


inline USHORT GetUDPHeaderLength(PUDP_HEADER header) {
	return CONVERT_NETE_16(header->Length);
}

inline VOID SetUDPHeaderLength(PUDP_HEADER header, USHORT length) {
	header->Length = CONVERT_NETE_16(length);
}


inline USHORT GetUDPHeaderChecksum(PUDP_HEADER header) {
	return CONVERT_NETE_16(header->Checksum);
}

inline VOID SetUDPHeaderChecksum(PUDP_HEADER header, USHORT checksum) {
	header->Checksum = CONVERT_NETE_16(checksum);
}


inline PVOID GetApplicationLayerHeaderFromUDPHeader(PUDP_HEADER header) {
	return (PVOID)((BYTE*)header + sizeof(UDP_HEADER));
}

