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
#include <ntifs.h>

#define HOOK_LIST_COUNT 5
#define BYTE unsigned char

#define WINPFILTER_HOOK_MANAGEMENT_DEVICE_NAME L"\\Device\\WinpfilterR0HookCommunicationDevice"

typedef ULONG FILTER_POINT;

#define FILTER_POINT_PREROUTING	 0
#define FILTER_POINT_INPUT		 1
#define FILTER_POINT_FORWARDING	 2
#define FILTER_POINT_OUTPUT		 3
#define FILTER_POINT_POSTROUTING 4

typedef  ULONG HOOK_ACTION;

// HOOK_ACTION values
// Drop the packet 
#define HOOK_ACTION_DROP			0
// Accept the packet 
#define HOOK_ACTION_ACCEPT			1
// The hook function modified the data in buffer
#define HOOK_ACTION_MODIFIED		2
// Accept the packet and truncate this Winpfilter hook processing chain
#define HOOK_ACTION_TRUNCATE_CHAIN	3

#define WINPFILTER_CTL_CODE_REGISTER_HOOK	CTL_CODE(FILE_DEVICE_UNKNOWN,0x800, METHOD_BUFFERED,FILE_ALL_ACCESS)
#define WINPFILTER_CTL_CODE_UNREGISTER_HOOK	CTL_CODE(FILE_DEVICE_UNKNOWN,0x801, METHOD_BUFFERED,FILE_ALL_ACCESS)

#pragma pack (1)
typedef struct _WINPFILTER_HOOK_OP_STRUCTURE
{
	ULONG Mode;
	PVOID HookFunction;
	ULONG Priority;
	FILTER_POINT FilterPoint;
}WINPFILTER_HOOK_OP_STRUCTURE, * PWINPFILTER_HOOK_OP_STRUCTURE;
#pragma pack ()