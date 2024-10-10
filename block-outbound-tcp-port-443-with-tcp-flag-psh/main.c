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
#include "tcp.h"
#include "ipv6.h"

 // This project demonstrate basic filter features with winpfilter framework
 // DO NOT USE IT IN PRODUCTION unless adjust the parameters 
 // and consider more in complex circumstances 


UNICODE_STRING DeviceName;
PDEVICE_OBJECT WinpfilterR0HookCommunicationDeviceObject = NULL;
PFILE_OBJECT WinpfilterR0HookCommunicationFileObject = NULL;

HOOK_ACTION BlockTCPPort443WithFlagPSH(ULONGLONG InterfaceLuid, FILTER_POINT FilterPoint, BYTE* Buffer, ULONG BufferLength, ULONG* pDataLength) {

	PETH_HEADER EthHeader = (PETH_HEADER)(Buffer);
	if (GetEtherHeaderProtocol(EthHeader) == ETH_PROTOCOL_IP) {
		PIPV4_HEADER IPv4Header = (PIPV4_HEADER)GetNetworkLayerHeaderFromEtherHeader(EthHeader);
		if (GetIPv4HeaderProtocol(IPv4Header) == 6) { // TCP
			PTCP_HEADER TcpHeader = (PTCP_HEADER)GetTransportLayerHeaderFromIPv4Header(IPv4Header);
			if (GetTCPHeaderDestPort(TcpHeader) == 443 && GetTCPHeaderFlagsPSH(TcpHeader)) { // Port 443 with PSH Flag
				return HOOK_ACTION_DROP;
			}
		}
	}
	else if (GetEtherHeaderProtocol(EthHeader) == ETH_PROTOCOL_IPV6) {
		PIPV6_HEADER IPv6Header = (PIPV6_HEADER)GetNetworkLayerHeaderFromEtherHeader(EthHeader);
		if (GetTransportLayerProtocolFromIPv6Header(IPv6Header) == 6) { // TCP
			PTCP_HEADER TcpHeader = (PTCP_HEADER)GetTransportLayerHeaderFromIPv6Header(IPv6Header);
			if (GetTCPHeaderDestPort(TcpHeader) == 443 && GetTCPHeaderFlagsPSH(TcpHeader)) { // Port 443 with PSH Flag
				return HOOK_ACTION_DROP;
			}
		}
	}
	
	return HOOK_ACTION_ACCEPT;
}


VOID UnregisterAllHooks() {
	IO_STATUS_BLOCK StatusBlock;
	PIRP RegisterIPv4DNSRedirectionIRP;
	if (WinpfilterR0HookCommunicationDeviceObject != NULL) {
		
		WINPFILTER_HOOK_OP_STRUCTURE RegisterIPv4RedirectDNSResponse;
		RtlZeroMemory(&RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE));
		RegisterIPv4RedirectDNSResponse.HookFunction = (PVOID)BlockTCPPort443WithFlagPSH;
		RegisterIPv4RedirectDNSResponse.Priority = 1026;
		RegisterIPv4RedirectDNSResponse.FilterPoint = FILTER_POINT_OUTPUT;
		RegisterIPv4DNSRedirectionIRP = IoBuildDeviceIoControlRequest((ULONG)WINPFILTER_CTL_CODE_UNREGISTER_HOOK, WinpfilterR0HookCommunicationDeviceObject, &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), FALSE, NULL, &StatusBlock);
		IoCallDriver(WinpfilterR0HookCommunicationDeviceObject, RegisterIPv4DNSRedirectionIRP);

	}
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UnregisterAllHooks();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	NTSTATUS Status = STATUS_SUCCESS;

	do
	{
		DriverObject->DriverUnload = DriverUnload;

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

		WINPFILTER_HOOK_OP_STRUCTURE RegisterIPv4RedirectDNSResponse;
		RtlZeroMemory(&RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE));
		RegisterIPv4RedirectDNSResponse.HookFunction = (PVOID)BlockTCPPort443WithFlagPSH;
		RegisterIPv4RedirectDNSResponse.Priority = 1026;
		RegisterIPv4RedirectDNSResponse.FilterPoint = FILTER_POINT_OUTPUT;
		RegisterIPv4DNSRedirectionIRP = IoBuildDeviceIoControlRequest((ULONG)WINPFILTER_CTL_CODE_REGISTER_HOOK, WinpfilterR0HookCommunicationDeviceObject, &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), &RegisterIPv4RedirectDNSResponse, sizeof(WINPFILTER_HOOK_OP_STRUCTURE), FALSE, NULL, &StatusBlock);
		Status = IoCallDriver(WinpfilterR0HookCommunicationDeviceObject, RegisterIPv4DNSRedirectionIRP);
		if (!NT_SUCCESS(Status)) {
			break;
		}

	} while (FALSE);

	if (!NT_SUCCESS(Status)) {
		UnregisterAllHooks();
	}

	return Status;
}