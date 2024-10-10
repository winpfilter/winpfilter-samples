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


#if  BIG_ENDIAN
inline USHORT CONVERT_NETE_16(USHORT u16_val) {
	return u16_val;
}
#else
inline USHORT CONVERT_NETE_16(USHORT u16_val) {
	return (USHORT)(((u16_val & 0xff) << 8) | (u16_val >> 8));
}
#endif
#if  BIG_ENDIAN
inline ULONG CONVERT_NETE_16(ULONG u32_val) {
	return u32_val;
}
#else
inline ULONG CONVERT_NETE_32(ULONG u32_val) {
	return (ULONG)(((u32_val & 0xff) << 24) | ((u32_val & 0xff00) << 8) | ((u32_val & 0xff0000) >> 8) | (u32_val >> 24));
}
#endif
