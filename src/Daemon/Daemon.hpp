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

#include "Typedefs.hpp"
#include "ConfigFile.hpp"
#include "IPC.hpp"
#include "IPCServer.hpp"
#include "RuleSet.hpp"
#include "Rule.hpp"
#include "Device.hpp"
#include "DeviceManager.hpp"
#include "DeviceManagerHooks.hpp"

#include "Common/Thread.hpp"
#include "Common/JSON.hpp"

#include <mutex>

namespace usbguard
{
  class Daemon : public IPCServer, public DeviceManagerHooks
  {
  public:
    enum PresentDevicePolicy {
      Allow,
      Block,
      Reject,
      Keep,
      ApplyPolicy
    };

    Daemon();
    ~Daemon();

    void loadConfiguration(const String& path);
    void loadRules(const String& path);

    void setImplicitPolicyTarget(Rule::Target target);
    void setPresentDevicePolicy(PresentDevicePolicy policy);
    void setPresentControllerPolicy(PresentDevicePolicy policy);

    /* Start the daemon */
    void run();
    /* Stop the daemon */
    void quit();

    uint32_t assignID();
    uint32_t upsertRule(const std::string& match_spec, const std::string& rule_spec, bool parent_insensitive = false);

    /* IPC methods */
    uint32_t appendRule(const std::string& rule_spec, uint32_t parent_id, uint32_t timeout_sec);
    void removeRule(uint32_t id);
    const RuleSet listRules();

    void allowDevice(uint32_t id, bool permanent,  uint32_t timeout_sec);
    void blockDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    void rejectDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    const std::vector<Rule> listDevices(const std::string& query);

    /* Device manager hooks */
    void dmHookDeviceInserted(Pointer<Device> device);
    void dmHookDevicePresent(Pointer<Device> device);
    void dmHookDeviceRemoved(Pointer<Device> device);
    void dmHookDeviceAllowed(Pointer<Device> device);
    void dmHookDeviceBlocked(Pointer<Device> device);
    void dmHookDeviceRejected(Pointer<Device> device);
    uint32_t dmHookAssignID();

    static PresentDevicePolicy presentDevicePolicyFromString(const String& policy_string);

  private:
    void allowDevice(uint32_t id, Pointer<const Rule> matched_rule);
    void blockDevice(uint32_t id, Pointer<const Rule> matched_rule);
    void rejectDevice(uint32_t id, Pointer<const Rule> matched_rule);

    Pointer<const Rule> upsertDeviceRule(uint32_t id, Rule::Target target, uint32_t timeout_sec);

    void DACAddAllowedUID(uid_t uid);
    void DACAddAllowedGID(gid_t gid);
    void DACAddAllowedUID(const String& username);
    void DACAddAllowedGID(const String& groupname);

  private:
    ConfigFile _config;
    RuleSet _ruleset;
    Pointer<DeviceManager> _dm;
    qb_loop_t *_qb_loop;
    
    Rule::Target _implicit_policy_target;
    PresentDevicePolicy _present_device_policy;
    PresentDevicePolicy _present_controller_policy;
    bool _device_rules_with_port;
  };
} /* namespace usbguard */
