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

#include "hw/char/riscv_sys_proxy.h"
#include "exec/hwaddr.h"
#include "fesvr/memif.h"
#include "fesvr/syscall_host.h"
#include "fesvr/syscall.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <vector>

extern "C" void cpu_physical_memory_rw(hwaddr addr, void *buf, hwaddr len,
                                       bool is_write);
extern "C" void htif_sys_proxy_error_report(const char *message);

namespace impl {

class MemoryWrapper : public chunked_memif_t {
public:
    MemoryWrapper() {}

    void read_chunk(addr_t taddr, size_t len, void *dst) override {
        cpu_physical_memory_rw(taddr, dst, len, false);
    }

    void write_chunk(addr_t taddr, size_t len, const void *src) override {
        cpu_physical_memory_rw(taddr, const_cast<void *>(src), len, true);
    }

    void clear_chunk(addr_t taddr, size_t len) override {
        std::vector<uint8_t> zeros(chunk_max_size(), 0);

        for (size_t pos = 0; pos < len; pos += chunk_max_size()) {
            write_chunk(taddr + pos, std::min(len - pos, chunk_max_size()), zeros.data());
        }
    }

    size_t chunk_align() override { return 1; }
    size_t chunk_max_size() override { return 4096; }
};

class Host : public syscall_host_t {
public:
    Host(const char *cmdline) : exit_code_(0), memif_(&mem_) {
        init_target_args(cmdline);
    }

    void check_exit() {
        if (exit_code_) std::exit(exit_code());
    }

    void set_exit_code(int exit_code) override { exit_code_ = exit_code; }

    int exit_code() override { return exit_code_ >> 1; }
    memif_t &memif() override { return memif_; }
    const std::vector<std::string> &target_args() override { return targs_; }

private:
    void init_target_args(const char *cmdline) {
        if (!cmdline) return;
        const char *p = cmdline;
        std::string arg;
        auto push_arg = [this, &p, &cmdline, &arg]() {
            if (!arg.empty() || (p != cmdline && (*(p - 1) == '\'' || *(p - 1) == '"'))) {
                targs_.emplace_back(std::move(arg));
            }
        };
        while (*p) {
            switch (*p) {
                case ' ': {
                    push_arg();
                    break;
                }
                case '\'':
                case '"': {
                    char quote = *p++;
                    while (*p && *p != quote) {
                        if (*p == '\\' && *(p + 1)) {
                            p++;
                            arg += *p == quote || *p == '\\' ? *p++ : '\\';
                        } else {
                            arg += *p++;
                        }
                    }
                    break;
                }
                case '\\': {
                    if (*(p + 1)) arg += *++p;
                    break;
                }
                default: {
                    arg += *p;
                    break;
                }
            }
            p++;
        }
        push_arg();
    }

    MemoryWrapper mem_;
    int exit_code_;
    memif_t memif_;
    std::vector<std::string> targs_;
};

class SyscallProxy {
public:
    SyscallProxy(const char *cmdline) : host_(cmdline), syscall_(&host_) {}

    void handle_command(command_t cmd) { syscall_.handle_command(cmd); }
    void check_exit() { host_.check_exit(); }

    memif_t &memif() { return host_.memif(); }

private:
    Host host_;
    syscall_t syscall_;
};

} // namespace impl

SyscallProxy sys_proxy_init(const char *cmdline)
{
    return new impl::SyscallProxy(cmdline);
}

int sys_proxy_handle_command(SyscallProxy sys_proxy, uint64_t tohost)
{
    impl::SyscallProxy *sp = reinterpret_cast<impl::SyscallProxy *>(sys_proxy);
    uint16_t fromhost = 0;
    command_t cmd(sp->memif(), tohost, [&fromhost](uint16_t f) { fromhost = f; });
    try {
        sp->handle_command(cmd);
    } catch (std::runtime_error &e) {
        htif_sys_proxy_error_report(e.what());
        std::exit(1);
    }
    sp->check_exit();
    return fromhost & 0xffffffff;
}
