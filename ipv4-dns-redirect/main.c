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

#include <ntifs.h>	
#include "winpfilter.h"
#include "ether.h"
#include "ipv4.h"
#include "udp.h"

// In this program, we just give an example for the simplest 
// DNS packet redirection. 
// DO NOT USE IT IN PRODUCTION unless adjust the parameters 
// and consider more in complex circumstances 

#define DNS_MAPPING_POOL_TAG 'DMPI'
#define REDIRECT_DNS_ADDRESS 0x08080808 //8.8.8.8

typedef struct _DNS_MAPPING_INFO {
	LIST_ENTRY Link;
	KDPC DPCRoutine;
	KTIMER Timer;
	ULONG SrcIP;
	USHORT SrcPort;
	ULONG DestIP;
	USHORT DestPort;
}DNS_MAPPING_INFO,*PDNS_MAPPING_INFO;

LIST_ENTRY DNSMappingInfoHead;
KSPIN_LOCK DNSMappingInfoLock;

VOID DestoryMappingInfo(PKDPC Dpc,PVOID DeferredContext,PVOID SystemArgument1,PVOID SystemArgument2){
	PDNS_MAPPING_INFO Info = DeferredContext;
	KIRQL OldIrql;
	KeAcquireSpinLock(&DNSMappingInfoLock, &OldIrql);
	RemoveEntryList(&Info->Link);
	KeCancelTimer(&Info->Timer);
	ExFreePoolWithTag(Info, DNS_MAPPING_POOL_TAG);
	KeReleaseSpinLock(&DNSMappingInfoLock, OldIrql);
}

HOOK_ACTION IPv4RedirectDNSQuery(ULONGLONG InterfaceLuid, FILTER_POINT FilterPoint, BYTE* Buffer, ULONG BufferLength, ULONG* pDataLength) {

	PETH_HEADER EthHeader = (PETH_HEADER)(Buffer);
	if (ETH_HEADER_PROTOCOL(EthHeader) != ETH_PROTOCOL_IP) {
		return HOOK_ACTION_ACCEPT;
	}
	PIPV4_HEADER IPv4Header = (PIPV4_HEADER)GetNetworkLayerHeaderFromEtherHeader(EthHeader);
	if (IPv4Header->Version != 4 || IPV4_HEADER_PROTOCOL(IPv4Header) != 17) { // UDP protocol : 17
		return HOOK_ACTION_ACCEPT;
	}
	PUDP_HEADER UDPHeader = (PUDP_HEADER)GetTransportLayerHeaderFromIPv4Header(IPv4Header);
	if (UDP_HEADER_DEST_PORT(UDPHeader) != 53) {
		return HOOK_ACTION_ACCEPT;
	}
	// To udp port 53. Dns packet, redirect it!
	PDNS_MAPPING_INFO Info = ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(DNS_MAPPING_INFO), DNS_MAPPING_POOL_TAG);
	if (Info == NULL) {
		return HOOK_ACTION_DROP;
	}
	Info->SrcIP = IPV4_HEADER_SRC_ADDR(IPv4Header);
	Info->SrcPort = UDP_HEADER_SRC_PORT(UDPHeader);
	Info->DestIP = IPV4_HEADER_DEST_ADDR(IPv4Header);
	Info->DestPort = UDP_HEADER_DEST_PORT(UDPHeader);
	KIRQL OldIrql;
	KeAcquireSpinLock(&DNSMappingInfoLock, &OldIrql);
	InsertHeadList(&DNSMappingInfoHead,&Info->Link);
	KeInitializeDpc(&Info->DPCRoutine, DestoryMappingInfo, Info);
	KeInitializeTimer(&Info->Timer);
	LARGE_INTEGER DueTime;
	// timeout: 10s
	DueTime.QuadPart = -10000 * 10000;
	KeSetTimer(&Info->Timer, DueTime, &Info->DPCRoutine);
	KeReleaseSpinLock(&DNSMappingInfoLock, OldIrql);

	// Set dst address to 8.8.8.8
	SET_IPV4_HEADER_DEST_ADDR(IPv4Header, REDIRECT_DNS_ADDRESS);
	return HOOK_ACTION_MODIFIED;
}

HOOK_ACTION IPv4RedirectDNSResponse(ULONGLONG InterfaceLuid, FILTER_POINT FilterPoint, BYTE* Buffer, ULONG BufferLength, ULONG* pDataLength) {

	PETH_HEADER EthHeader = (PETH_HEADER)(Buffer);
	if (ETH_HEADER_PROTOCOL(EthHeader) != ETH_PROTOCOL_IP) {
		return HOOK_ACTION_ACCEPT;
	}
	PIPV4_HEADER IPv4Header = (PIPV4_HEADER)GetNetworkLayerHeaderFromEtherHeader(EthHeader);
	if (IPv4Header->Version != 4 || IPV4_HEADER_PROTOCOL(IPv4Header) != 17) { // UDP protocol : 17
		return HOOK_ACTION_ACCEPT;
	}
	PUDP_HEADER UDPHeader = (PUDP_HEADER)GetTransportLayerHeaderFromIPv4Header(IPv4Header);
	if (UDP_HEADER_SRC_PORT(UDPHeader) != 53 || IPV4_HEADER_SRC_ADDR(IPv4Header) != REDIRECT_DNS_ADDRESS) {
		return HOOK_ACTION_ACCEPT;
	}

	// From 8.8.8.8:53
	KIRQL OldIrql;
	KeAcquireSpinLock(&DNSMappingInfoLock, &OldIrql);
	for (PLIST_ENTRY i =DNSMappingInfoHead.Blink; i != &DNSMappingInfoHead; i=i->Blink) {
		USHORT DstPort = UDP_HEADER_DEST_PORT(UDPHeader);
		ULONG DstIP = IPV4_HEADER_DEST_ADDR(IPv4Header);
		PDNS_MAPPING_INFO MappingInfo = CONTAINING_RECORD(i, DNS_MAPPING_INFO, Link);
		if (DstIP == MappingInfo->SrcIP && DstPort == MappingInfo->SrcPort) {
			SET_IPV4_HEADER_SRC_ADDR(IPv4Header, MappingInfo->DestIP);

			KeReleaseSpinLock(&DNSMappingInfoLock, OldIrql);
			return HOOK_ACTION_MODIFIED;
		}
	}
	KeReleaseSpinLock(&DNSMappingInfoLock, OldIrql);

	return HOOK_ACTION_DROP;
}


UNICODE_STRING DeviceName;
PDEVICE_OBJECT WinpfilterR0HookCommunicationDeviceObject = NULL;
PFILE_OBJECT WinpfilterR0HookCommunicationFileObject = NULL;


VOID UnregisterAllHooks ()  {
		IO_STATUS_BLOCK StatusBlock;
		PIRP RegisterIPv4DNSRedirectionIRP;
		if (WinpfilterR0HookCommunicationDeviceObject != NULL) {

			WINPFILTER_HOOK_OP_STRUCTURE RegisterIPv4RedirectDNSQuery;
			RtlZeroMemory(&RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE));
			RegisterIPv4RedirectDNSQuery.HookFunction = (PVOID)IPv4RedirectDNSQuery;
			RegisterIPv4RedirectDNSQuery.Priority = 1025;
			RegisterIPv4RedirectDNSQuery.FilterPoint = FILTER_POINT_POSTROUTING;
			RegisterIPv4DNSRedirectionIRP = IoBuildDeviceIoControlRequest((ULONG)WINPFILTER_CTL_CODE_UNREGISTER_HOOK, WinpfilterR0HookCommunicationDeviceObject, &RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), &RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), FALSE, NULL, &StatusBlock);
			IoCallDriver(WinpfilterR0HookCommunicationDeviceObject, RegisterIPv4DNSRedirectionIRP);

			WINPFILTER_HOOK_OP_STRUCTURE RegisterIPv4RedirectDNSResponse;
			RtlZeroMemory(&RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE));
			RegisterIPv4RedirectDNSResponse.HookFunction = (PVOID)IPv4RedirectDNSResponse;
			RegisterIPv4RedirectDNSResponse.Priority = 1025;
			RegisterIPv4RedirectDNSResponse.FilterPoint = FILTER_POINT_PREROUTING;
			RegisterIPv4DNSRedirectionIRP = IoBuildDeviceIoControlRequest((ULONG)WINPFILTER_CTL_CODE_UNREGISTER_HOOK, WinpfilterR0HookCommunicationDeviceObject, &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), &RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), FALSE, NULL, &StatusBlock);
			IoCallDriver(WinpfilterR0HookCommunicationDeviceObject, RegisterIPv4DNSRedirectionIRP);

		}
		
}

VOID FreeDNSMappingList() {
	KIRQL OldIrql;
	KeAcquireSpinLock(&DNSMappingInfoLock, &OldIrql);
	PLIST_ENTRY i = DNSMappingInfoHead.Blink;
	PLIST_ENTRY n = NULL;
	while (i != &DNSMappingInfoHead) {
		n = i->Blink;
		PDNS_MAPPING_INFO MappingInfo = CONTAINING_RECORD(i, DNS_MAPPING_INFO, Link);
		RemoveEntryList(&MappingInfo->Link);
		KeCancelTimer(&MappingInfo->Timer);
		ExFreePoolWithTag(MappingInfo, DNS_MAPPING_POOL_TAG);
		i = n;
	}

	KeReleaseSpinLock(&DNSMappingInfoLock, OldIrql);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UnregisterAllHooks();
	FreeDNSMappingList();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	NTSTATUS Status = STATUS_SUCCESS;

	do
	{
		DriverObject->DriverUnload = DriverUnload;

		InitializeListHead(&DNSMappingInfoHead);
		KeInitializeSpinLock(&DNSMappingInfoLock);
		RtlInitUnicodeString(&DeviceName, WINPFILTER_HOOK_MANAGEMENT_DEVICE_NAME);

		Status = IoGetDeviceObjectPointer(&DeviceName, FILE_ALL_ACCESS, &WinpfilterR0HookCommunicationFileObject, &WinpfilterR0HookCommunicationDeviceObject);
		if (!NT_SUCCESS(Status)) {
			break;
		}
		if (WinpfilterR0HookCommunicationFileObject != NULL) {
			ObDereferenceObject(WinpfilterR0HookCommunicationFileObject);
		}
		IO_STATUS_BLOCK StatusBlock;
		PIRP RegisterIPv4DNSRedirectionIRP;
		WINPFILTER_HOOK_OP_STRUCTURE RegisterIPv4RedirectDNSQuery;
		RtlZeroMemory(&RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE));
		RegisterIPv4RedirectDNSQuery.HookFunction = (PVOID)IPv4RedirectDNSQuery;
		RegisterIPv4RedirectDNSQuery.Priority = 1025;
		RegisterIPv4RedirectDNSQuery.FilterPoint = FILTER_POINT_POSTROUTING;
		RegisterIPv4DNSRedirectionIRP = IoBuildDeviceIoControlRequest((ULONG)WINPFILTER_CTL_CODE_REGISTER_HOOK, WinpfilterR0HookCommunicationDeviceObject, &RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), &RegisterIPv4RedirectDNSQuery, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), FALSE, NULL, &StatusBlock);
		Status = IoCallDriver(WinpfilterR0HookCommunicationDeviceObject, RegisterIPv4DNSRedirectionIRP);
		if (!NT_SUCCESS(Status)) {
			break;
		}

		WINPFILTER_HOOK_OP_STRUCTURE RegisterIPv4RedirectDNSResponse;
		RtlZeroMemory(&RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE));
		RegisterIPv4RedirectDNSResponse.HookFunction = (PVOID)IPv4RedirectDNSResponse;
		RegisterIPv4RedirectDNSResponse.Priority = 1025;
		RegisterIPv4RedirectDNSResponse.FilterPoint = FILTER_POINT_PREROUTING;
		RegisterIPv4DNSRedirectionIRP = IoBuildDeviceIoControlRequest((ULONG)WINPFILTER_CTL_CODE_REGISTER_HOOK, WinpfilterR0HookCommunicationDeviceObject, &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), FALSE, NULL, &StatusBlock);
		Status = IoCallDriver(WinpfilterR0HookCommunicationDeviceObject, RegisterIPv4DNSRedirectionIRP);
		if (!NT_SUCCESS(Status)) {
			break;
		}

	} while (FALSE);

	if (!NT_SUCCESS(Status)) {
		UnregisterAllHooks();
		FreeDNSMappingList();
	}

	return Status;
}