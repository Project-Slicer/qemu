/*
 * System Call Proxy in RISC-V Host Target Interface (HTIF)
 *
 * Copyright (c) 2022 Max Xing, x@maxxsoft.net
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_RISCV_SYS_PROXY_H
#define HW_RISCV_SYS_PROXY_H

#include <stdint.h>

typedef void *SyscallProxy;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the system call proxy */
SyscallProxy sys_proxy_init(const char *filename, const char *cmdline);

/* Handle the command from the target */
int sys_proxy_handle_command(SyscallProxy sys_proxy, uint64_t tohost);

#ifdef __cplusplus
}
#endif

#endif
