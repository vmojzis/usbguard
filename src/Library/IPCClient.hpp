//
// Copyright (C) 2015 Red Hat, Inc.
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
#pragma once
#include <Typedefs.hpp>
#include <IPC.hpp>

namespace usbguard
{
  class IPCClientPrivate;
  class DLL_PUBLIC IPCClient : public Interface
  {
  public:
    IPCClient(bool connected = false);
    virtual ~IPCClient();

    void connect();
    void disconnect();
    bool isConnected() const;
    void wait();

    uint32_t appendRule(const std::string& rule_spec, uint32_t parent_id, uint32_t timeout_sec);
    void removeRule(uint32_t id);
    const RuleSet listRules();
    void allowDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    void blockDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    void rejectDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    const std::vector<Rule> listDevices(const std::string& query);
    const std::vector<Rule> listDevices() /* NOTE: left for compatibility */
    {
      return listDevices("match");
    }

    virtual void IPCConnected() {}
    virtual void IPCDisconnected(bool exception_initiated, const IPCException& exception) {}

    virtual void DeviceInserted(uint32_t id,
                const std::map<std::string,std::string>& attributes,
                const std::vector<USBInterfaceType>& interfaces,
                bool rule_match,
                uint32_t rule_id) {}

    virtual void DevicePresent(uint32_t id,
                   const std::map<std::string,std::string>& attributes,
                   const std::vector<USBInterfaceType>& interfaces,
                   Rule::Target target) {}

    virtual void DeviceRemoved(uint32_t id,
                   const std::map<std::string,std::string>& attributes) {}

    virtual void DeviceAllowed(uint32_t id,
                   const std::map<std::string,std::string>& attributes,
                   bool rule_match,
                   uint32_t rule_id) {}

    virtual void DeviceBlocked(uint32_t id,
                   const std::map<std::string,std::string>& attributes,
                   bool rule_match,
                   uint32_t rule_id) {}

    virtual void DeviceRejected(uint32_t id,
                const std::map<std::string,std::string>& attributes,
                bool rule_match,
                uint32_t rule_id) {}

  private:
    IPCClientPrivate* d_pointer;
  };

} /* namespace usbguard */
