// Copyright 2026 FlagOS Contributors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace flagscale_trace {
inline const char* collector_path() {
  const char* path = std::getenv("FLAGSCALE_TRACE_COLLECTOR_SOCKET");
  return path && *path ? path : nullptr;
}

inline int connect_collector(const char* path) {
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  if (std::strlen(path) >= sizeof(address.sun_path)) { errno = ENAMETOOLONG; return -1; }
  std::memcpy(address.sun_path, path, std::strlen(path) + 1);
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) return -1;
  // A saturated local collector must not stall NCCL initialization. After
  // connecting, only the asynchronous publisher uses the blocking descriptor.
  if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
      ::fcntl(fd, F_SETFL, 0) == 0) return fd;
  const int error = errno;
  ::close(fd);
  errno = error;
  return -1;
}
}  // namespace flagscale_trace
