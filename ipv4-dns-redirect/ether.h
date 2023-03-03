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

#define MAC_LENGTH	6					

#define ETH_PROTOCOL_IP		0x0800U		
#define ETH_PROTOCOL_ARP	0x0806U		
#define ETH_PROTOCOL_8021Q	0x8100U    
#define ETH_PROTOCOL_IPV6	0x86DDU	

#pragma pack (1)
typedef struct _ETH_HEADER
{
	BYTE DestMAC[MAC_LENGTH];			
	BYTE SrcMac[MAC_LENGTH];	
	USHORT Protocol;				
}ETH_HEADER,*PETH_HEADER;
#pragma pack ()

#define ETH_HEADER_PROTOCOL(header)						(CONVERT_NETE_16((header)->Protocol))

#define SET_ETH_HEADER_PROTOCOL(header,protocol)		((header)->Protocol = CONVERT_NETE_16(protocol))

#define GetNetworkLayerHeaderFromEtherHeader(ethheader)		((BYTE*)(((BYTE*)ethheader) + sizeof(ETH_HEADER)))