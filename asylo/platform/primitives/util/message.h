/*
 *
 * Copyright 2019 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_MESSAGE_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_MESSAGE_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace primitives {

// A message serialization implementation to allow the users to pass input data
// via extents and generate a serialized message. The MessageReader is a
// serialization utility designed to make it easier and safer to pass structured
// data over the enclave boundary. The extents pushed to the MessageWriter are
// serialized using |Serialize()|, passed across the enclave boundary and
// deserialized using the MessageReader for consumption. The message is simply
// comprised of a data pointer and the size.
//
// The message writer only allows pushing extents or values to it; reading data
// from the writer is disallowed. The message writer does not perform memory
// allocation for the serialized message. Extents can be pushed by reference or
// by copy, in which case they are owned by the MessageWriter.
class MessageWriter {
 public:
  MessageWriter() = default;

  // Disallow copying.
  MessageWriter(const MessageWriter &other) = delete;
  MessageWriter operator=(const MessageWriter &other) = delete;

  // Allow moving.
  MessageWriter(MessageWriter &&other) noexcept = default;
  MessageWriter &operator=(MessageWriter &&other) = default;

  // Returns true if no output has been written to the MessageWriter.
  bool empty() const { return extents_.empty(); }

  // Returns the number of extents pushed on the writer.
  size_t size() const { return extents_.size(); }

  // Returns the size of serialized message generated by Serialize().
  size_t MessageSize() const {
    size_t result = sizeof(uint64_t) * extents_.size();
    for (const auto &extent : extents_) {
      result += extent.size();
    }
    return result;
  }

  // Generates and writes a serialized message into |buffer| owned by
  // the caller, which must accommodate at least MessageSize() bytes.
  void Serialize(void *buffer) const {
    if (extents_.empty()) {
      return;
    }
    auto ptr = reinterpret_cast<char *>(buffer);
    for (const auto &extent : extents_) {
      uint64_t size = extent.size();
      memcpy(ptr, &size, sizeof(uint64_t));  // Copy data size.
      ptr += sizeof(uint64_t);
      memcpy(ptr, extent.data(), size);  // Copy data.
      ptr += size;
    }
  }

  // Serializes data using a given serializer.
  void Serialize(const std::function<void(Extent)> &serializer) const {
    for (const auto &extent : extents_) {
      serializer(extent);
    }
  }

  // Pushes an extent to the MessageWriter by reference.
  void PushByReference(Extent extent) { extents_.emplace_back(extent); }

  // Pushes an extent to the MessageWriter by copy. Data is copied and owned by
  // the MessageWriter.
  void PushByCopy(Extent extent) {
    char *extent_data = new char[extent.size()];
    copied_data_owner_.emplace_back(extent_data);
    memcpy(extent_data, extent.data(), extent.size());
    PushByReference(Extent{extent_data, extent.size()});
  }

  // Pushes non-pointer data types (eg. ints, structs) by value. Internally
  // performs a copy, since the input value could go out of scope after being
  // pushed.
  template <typename T>
  void Push(const T &value) {
    static_assert(!std::is_pointer<T>::value,
                  "PushByValue should not be used with pointers");
    PushByCopy(Extent{const_cast<T *>(&value)});
  }

  // Pushes a string by copy, including a trailing null character for ease of
  // compatibility with C-style string consumers.
  void PushString(const std::string &s) {
    PushByCopy(Extent{s.c_str(), s.size() + 1});
  }

  // Pushes a string by copy.
  void PushString(const char *s) {
    if (s) {
      PushByCopy(Extent{s, strlen(s) + 1});
    } else {
      PushByCopy(Extent{nullptr, 0});
    }
  }

  // Pushes a string by copy, passing an explicit length in bytes. This variant
  // pushes exactly |length| bytes and does not add a trailing null terminator.
  void PushString(const char *s, size_t length) {
    PushByCopy(Extent{s, length});
  }

  // Determines the type of a sockaddr and pushes it on the MessageWriter.
  PrimitiveStatus PushSockAddr(struct sockaddr *sock) {
    if (!sock) {
      PushByCopy(Extent{nullptr, 0});
    } else if (sock->sa_family == AF_UNIX) {
      PushByCopy(
          Extent{reinterpret_cast<char *>(sock), sizeof(struct sockaddr_un)});
    } else if (sock->sa_family == AF_INET) {
      PushByCopy(
          Extent{reinterpret_cast<char *>(sock), sizeof(struct sockaddr_in)});
    } else if (sock->sa_family == AF_INET6) {
      PushByCopy(
          Extent{reinterpret_cast<char *>(sock), sizeof(struct sockaddr_in6)});
    } else {
      return {error::GoogleError::INVALID_ARGUMENT,
              "PushSockAddr: Unsupported sa_family encountered."};
    }
    return PrimitiveStatus::OkStatus();
  }

  // Copies the extents of |other| to this MessageWriter.
  void Extend(const MessageWriter &other) {
    for (const auto extent : other.extents_) {
      PushByCopy(extent);
    }
  }

 private:
  std::vector<Extent> extents_;
  std::vector<std::unique_ptr<char[]>> copied_data_owner_;
};

// A message reader that consumes a serialized message and generates extents.
// The extent memory is owned by the class and freed with the destructor.
// Extents can be read from the MessageReader only once, and never written.
class MessageReader {
 public:
  MessageReader() = default;

  // Disallow copying.
  MessageReader(const MessageReader &other) = delete;
  MessageReader operator=(const MessageReader &other) = delete;

  // Allow moving.
  MessageReader(MessageReader &&other) noexcept = default;
  MessageReader &operator=(MessageReader &&other) = default;

  // Deserializes a data buffer of provided size into owned extents. |buffer| is
  // the serialized buffer originally written by the MessageWriter, and is owned
  // by the user/runtime. |buffer| consists of |size| bytes. |buffer| could be
  // located in untrusted memory, and therefore, transferring its ownership to
  // trusted memory is non-trivial, since trusted memory would then need to
  // remotely manage untrusted memory. This necessitates deserializing and
  // copying |buffer| into new owned extents, since MessageReader is expected
  // to own its memory.
  void Deserialize(const void *buffer, size_t size) {
    const char *ptr = reinterpret_cast<const char *>(buffer);
    const char *end_ptr = ptr + size;
    while (ptr < end_ptr) {
      uint64_t extent_len;
      memcpy(&extent_len, ptr, sizeof(uint64_t));
      ptr += sizeof(uint64_t);
      char *extent_data = new char[extent_len];
      extents_.emplace_back(std::unique_ptr<char[]>(extent_data), extent_len);
      memcpy(extent_data, ptr, extent_len);
      ptr += extent_len;
    }
  }

  // Deserializes data using a given deserializer.
  void Deserialize(const size_t size,
                   const std::function<Extent(size_t i)> &deserializer) {
    extents_.reserve(size);
    for (size_t i = 0; i < size; ++i) {
      auto extent = deserializer(i);
      extents_.emplace_back(absl::make_unique<char[]>(extent.size()),
                            extent.size());
      if (extent.size() > 0) {
        memcpy(extents_.back().first.get(), extent.data(), extent.size());
      }
    }
  }

  // Returns the number of extents read.
  size_t size() const { return extents_.size(); }

  // Returns the next extent in the MessageReader. The MessageReader may only be
  // traversed once. The returned extent remains owned by the MessageReader and
  // its lifetime is the lifetime of the MessageReader.
  Extent next() {
    Extent result = peek();
    pos_++;
    return result;
  }

  // Interprets the next item in the MessageReader as a pointer to a value of
  // type T, consumes it, and returns its value by copy.
  template <typename T>
  T next() {
    Extent result = next();
    return *(result.As<T>());
  }

  // Peeks at the next extent in the MessageReader; the ensuing next() call will
  // return the same extent. The extent remains owned by the MessageReader and
  // its lifetime is the lifetime of the MessageReader.
  Extent peek() {
    return Extent{extents_[pos_].first.get(), extents_[pos_].second};
  }

  // Interprets the peek item in the MessageReader as a pointer to a value of
  // type T, consumes it, and returns its value by const reference.
  template <typename T>
  const T &peek() {
    Extent result = peek();
    return *(result.As<T>());
  }

  // Returns if the reader is empty, i.e. contains no extents.
  bool empty() const { return extents_.empty(); }

  // Returns if the reader traversal has reached the end.
  bool hasNext() const { return pos_ != size(); }

#define ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(reader, expected_args) \
  do {                                                                    \
    if ((reader).size() != expected_args) {                               \
      return {::asylo::error::GoogleError::INVALID_ARGUMENT,              \
              absl::StrCat(expected_args,                                 \
                           " item(s) expected on the MessageReader.")};   \
    }                                                                     \
  } while (false)

#define ASYLO_RETURN_IF_TOO_FEW_READER_ARGUMENTS(reader, expected_args) \
  do {                                                                  \
    if ((reader).size() < expected_args) {                              \
      return {::asylo::error::GoogleError::INVALID_ARGUMENT,            \
              absl::StrCat("At least", expected_args,                   \
                           " item(s) expected on the MessageReader.")}; \
    }                                                                   \
  } while (false)

#define ASYLO_RETURN_IF_READER_NOT_EMPTY(reader)             \
  do {                                                       \
    if (!(reader).empty()) {                                 \
      return {::asylo::error::GoogleError::INVALID_ARGUMENT, \
              "MessageReader expected to be empty."};        \
    }                                                        \
  } while (false)

#define ASYLO_RETURN_IF_READER_HAS_NEXT(reader)              \
  do {                                                       \
    if ((reader).hasNext()) {                                \
      return {::asylo::error::GoogleError::INVALID_ARGUMENT, \
              "More items than expected on the reader."};    \
    }                                                        \
  } while (false)

 private:
  std::vector<std::pair<std::unique_ptr<char[]>, size_t>> extents_;
  size_t pos_ = 0;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_MESSAGE_H_
