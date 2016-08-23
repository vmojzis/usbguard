//
// Copyright (C) 2016 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Authors: Daniel Kopecek <dkopecek@redhat.com>
//
#include "IPCPrivate.hpp"

#include <Devices.pb.h>
#include <Exception.pb.h>
#include <Policy.pb.h>

#include <vector>
#include <utility>

namespace usbguard
{
  static const std::vector<std::pair<uint32_t, std::string>> type_numbers = {
    { 0x01, "listDevicesRequest" },
    { 0x02, "listDevicesResponse" },
    { 0x03, "applyDevicePolicyRequest" },
    { 0x04, "applyDevicePolicyResponse" },
    { 0x05, "DevicePresenceChangedSignal" },
    { 0x06, "DevicePolicyChangedSignal" },
    { 0x07, "listRulesRequest" },
    { 0x08, "listRulesResponse" },
    { 0x09, "appendRuleRequest" },
    { 0x0a, "appendRuleResponse" },
    { 0x0b, "removeRuleRequest" },
    { 0x0c, "Exception" }
  };

  uint32_t IPC::messageTypeNameToNumber(const std::string& name)
  {
    for (auto const& type_number : type_numbers) {
      if (type_number.second == name) {
        return type_number.first;
      }
    }
    throw std::runtime_error("Unknown IPC message type name");
  }

  const std::string& IPC::messageTypeNameFromNumber(const uint32_t number)
  {
    for (auto const& type_number : type_numbers) {
      if (type_number.first == number) {
        return type_number.second;
      }
    }
    throw std::runtime_error("Unknown IPC message type number");
  }
} /* namespace usbguard */
