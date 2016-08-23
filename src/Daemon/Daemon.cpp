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
#include <build-config.h>

#include "Daemon.hpp"
#include "LoggerPrivate.hpp"
#include "Common/Utility.hpp"
#include "IPCPrivate.hpp"
#include "RulePrivate.hpp"
#include "RuleParser.hpp"

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <grp.h>
#include <pwd.h>

namespace usbguard
{
  qb_loop_t *G_qb_loop = nullptr;

  /*
   * Recognized configuration option names. If an
   * unknown setting is found in the config file,
   * a warning message will be displayed.
   */
  const StringVector G_config_known_names = {
    "RuleFile",
    "ImplicitPolicyTarget",
    "PresentDevicePolicy",
    "PresentControllerPolicy",
    "IPCAllowedUsers",
    "IPCAllowedGroups",
    "DeviceRulesWithPort"
  };

  Daemon::Daemon()
    : _config(G_config_known_names),
      _ruleset(this)
  {
    G_qb_loop = _qb_loop = qb_loop_create();

    if (!_qb_loop) {
      throw std::runtime_error("qb init error");
    }

    try {
      _dm = DeviceManager::create(*this);
    } catch(...) {
      qb_loop_destroy(_qb_loop);
      G_qb_loop = nullptr;
      throw;
    }

    for (int signum : { SIGINT, SIGTERM, SIGSYS }) {
      if (qb_loop_signal_add(_qb_loop, QB_LOOP_HIGH, signum,
			     _qb_loop, Daemon::qbSignalHandlerFn, NULL) != 0) {
	logger->debug("Cannot register signal #{} handler", signum);
	throw std::runtime_error("signal init error");
      }
    }

    _ipc_dac_acl = false;
    _implicit_policy_target = Rule::Target::Block;
    _present_device_policy = PresentDevicePolicy::Keep;
    _present_controller_policy = PresentDevicePolicy::Allow;
    _device_rules_with_port = false;
  }

  Daemon::~Daemon()
  {
    _config.close();
    qb_loop_destroy(_qb_loop);
    G_qb_loop = nullptr;
  }

  void Daemon::loadConfiguration(const String& path)
  {
    logger->debug("Loading configuration from {}", path);
    _config.open(path);

    /* RuleFile */
    if (_config.hasSettingValue("RuleFile")) {
      logger->debug("Setting rules file path from configuration file");
      const String& rule_file = _config.getSettingValue("RuleFile");
      try {
	loadRules(rule_file);
      }
      catch(const RuleParserError& ex) {
        logger->error("Syntax error in the rule file on line {}: {}", ex.line(), ex.hint());
        throw ex;
      }
      catch(const std::exception& ex) {
        logger->warn("The configured rule file doesn't yet exists. Starting with an empty rule set.");
      }
    } else {
      logger->debug("No rules file path specified.");
    }

    /* ImplicitPolicyTarget */
    if (_config.hasSettingValue("ImplicitPolicyTarget")) {
      const String& target_string = _config.getSettingValue("ImplicitPolicyTarget");
      Rule::Target target = Rule::targetFromString(target_string);
      setImplicitPolicyTarget(target);
    }

    /* PresentDevicePolicy */
    if (_config.hasSettingValue("PresentDevicePolicy")) {
      const String& policy_string = _config.getSettingValue("PresentDevicePolicy");
      PresentDevicePolicy policy = Daemon::presentDevicePolicyFromString(policy_string);
      setPresentDevicePolicy(policy);
    }

    /* PresentControllerPolicy */
    if (_config.hasSettingValue("PresentControllerPolicy")) {
      const String& policy_string = _config.getSettingValue("PresentControllerPolicy");
      PresentDevicePolicy policy = Daemon::presentDevicePolicyFromString(policy_string);
      setPresentControllerPolicy(policy);
    }

    /* IPCAllowedUsers */
    if (_config.hasSettingValue("IPCAllowedUsers")) {
      logger->debug("Setting allowed IPC users");
      StringVector usernames;
      tokenizeString(_config.getSettingValue("IPCAllowedUsers"),
		     usernames, " ", /*trim_empty=*/true);
      for (auto const& username : usernames) {
	logger->debug("Allowed IPC user: {}", username);
	DACAddAllowedUID(username);
      }
      _ipc_dac_acl = true;
    }

    /* IPCAllowedGroups */
    if (_config.hasSettingValue("IPCAllowedGroups")) {
      logger->debug("Setting allowed IPC groups");
      StringVector groupnames;
      tokenizeString(_config.getSettingValue("IPCAllowedGroups"),
		     groupnames, " ", /*trim_empty=*/true);
      for (auto const& groupname : groupnames) {
	logger->debug("Allowed IPC group: {}", groupname);
	DACAddAllowedGID(groupname);
      }
      _ipc_dac_acl = true;
    }

    /* DeviceRulesWithPort */
    if (_config.hasSettingValue("DeviceRulesWithPort")) {
      const String value = _config.getSettingValue("DeviceRulesWithPort");
      if (value == "true") {
        _device_rules_with_port = true;
      }
      else if (value == "false") {
        _device_rules_with_port = false;
      }
      else {
        throw std::runtime_error("Invalid DeviceRulesWithPort value.");
      }
      logger->debug("DeviceRulesWithPort set to {}", _device_rules_with_port);
    }

    logger->debug("Configuration loaded successfully");
    return;
  }

  void Daemon::loadRules(const String& path)
  {
    _ruleset.load(path);
    return;
  }

  void Daemon::setImplicitPolicyTarget(Rule::Target target)
  {
    _implicit_policy_target = target;
    _ruleset.setDefaultTarget(target);
    return;
  }

  void Daemon::setPresentDevicePolicy(PresentDevicePolicy policy)
  {
    _present_device_policy = policy;
    return;
  }

  void Daemon::setPresentControllerPolicy(PresentDevicePolicy policy)
  {
    _present_controller_policy = policy;
    return;
  }

  void Daemon::run()
  {
    _dm->start();
    qb_loop_run(_qb_loop);
    return;
  }

  void Daemon::quit()
  {
    qb_loop_stop(_qb_loop);
    return;
  }

  uint32_t Daemon::assignID()
  {
    return _ruleset.assignID();
  }

  /*
   * Search for a rule that matches `match_spec' rule and
   * update it with a rule specified by `rule_spec'. Fail
   * if multiple rules match. If there are no matching
   * rules, append the `rule_spec' rule.
   *
   * Return the id of the updated or new rule.
   */
  uint32_t Daemon::upsertRule(const std::string& match_spec,
                              const std::string& rule_spec,
                              const bool parent_insensitive)
  {
    const Rule match_rule = Rule::fromString(match_spec);
    const Rule new_rule = Rule::fromString(rule_spec);
    logger->debug("Upserting rule: match={}, new={}", match_spec, rule_spec);
    const uint32_t id = _ruleset.upsertRule(match_rule, new_rule, parent_insensitive);
    if (_config.hasSettingValue("RuleFile")) {
      _ruleset.save(_config.getSettingValue("RuleFile"));
    }
    return id;
  }

  /*
   * IPC service methods
   */
  uint32_t Daemon::appendRule(const std::string& rule_spec,
			      uint32_t parent_id,
			      uint32_t timeout_sec)
  {
    (void)timeout_sec; /* TODO */
    const Rule rule = Rule::fromString(rule_spec);
    /* TODO: reevaluate the firewall rules for all active devices */
    logger->debug("Appending rule: {}", rule_spec);
    const uint32_t id = _ruleset.appendRule(rule, parent_id);
    if (_config.hasSettingValue("RuleFile")) {
      _ruleset.save(_config.getSettingValue("RuleFile"));
    }
    return id;
  }

  void Daemon::removeRule(uint32_t id)
  {
    logger->debug("Removing rule: id={}", id);
    _ruleset.removeRule(id);
    if (_config.hasSettingValue("RuleFile")) {
      _ruleset.save(_config.getSettingValue("RuleFile"));
    }
    return;
  }

  const RuleSet Daemon::listRules()
  {
    return _ruleset;
  }

  void Daemon::allowDevice(uint32_t id, bool permanent, uint32_t timeout_sec)
  {
    logger->debug("Allowing device: {}", id);
    Pointer<const Rule> rule;
    if (permanent) {
      rule = upsertDeviceRule(id, Rule::Target::Allow, timeout_sec);
    }
    else {
      rule = makePointer<Rule>();
    }
    allowDevice(id, rule);
    return;
  }

  void Daemon::blockDevice(uint32_t id, bool permanent, uint32_t timeout_sec)
  {
    logger->debug("Blocking device: {}", id);
    Pointer<const Rule> rule;
    if (permanent) {
      rule = upsertDeviceRule(id, Rule::Target::Block, timeout_sec);
    }
    else {
      rule = makePointer<Rule>();
    }
    blockDevice(id, rule);
    return;
  }

  void Daemon::rejectDevice(uint32_t id, bool permanent, uint32_t timeout_sec)
  {
    logger->debug("Rejecting device: {}", id);
    Pointer<const Rule> rule;
    if (permanent) {
      rule = upsertDeviceRule(id, Rule::Target::Reject, timeout_sec);
    }
    else {
      rule = makePointer<Rule>();
    }
    rejectDevice(id, rule);
    return;
  }

  void Daemon::DeviceInserted(uint32_t id,
			      const std::map<std::string,std::string>& attributes,
			      const std::vector<USBInterfaceType>& interfaces,
			      bool rule_match,
			      uint32_t rule_id)
  {
    logger->debug("DeviceInserted: id={}, rule_match={}, rule_id={}",
		  id, rule_match, rule_id);

    json interfaces_json;
    for (auto const& type : interfaces) {
      interfaces_json.push_back(type.typeString());
    }

    const json j = {
      {         "_s", "DeviceInserted" },
      {       "id", id },
      { "attributes", attributes },
      { "interfaces", interfaces_json },
      { "rule_match", rule_match },
      {  "rule_id", rule_id }
    };

    qbIPCBroadcastJSON(j);
    return;
  }

  void Daemon::DevicePresent(uint32_t id,
			     const std::map<std::string,std::string>& attributes,
			     const std::vector<USBInterfaceType>& interfaces,
			     Rule::Target target)
  {
    logger->debug("DevicePresent: id={}, target={}", id, Rule::targetToString(target));

    json interfaces_json;
    for (auto const& type : interfaces) {
      interfaces_json.push_back(type.typeString());
    }

    const json j = {
      {         "_s", "DevicePresent" },
      {       "id", id },
      { "attributes", attributes },
      { "interfaces", interfaces_json },
      {     "target", Rule::targetToString(target) },
    };

    qbIPCBroadcastJSON(j);
    return;
  }

  void Daemon::DeviceRemoved(uint32_t id,
			     const std::map<std::string,std::string>& attributes)

  {
    logger->debug("DeviceRemoved: id={}", id);

    const json j = {
      {         "_s", "DeviceRemoved" },
      {       "id", id },
      { "attributes", attributes }
    };

    qbIPCBroadcastJSON(j);
    return;
  }

  void Daemon::DeviceAllowed(uint32_t id,
			     const std::map<std::string,std::string>& attributes,
			     bool rule_match,
			     uint32_t rule_id)
  {
    logger->debug("DeviceAllowed: id={}, rule_match={}, rule_id={}",
		  id, rule_match, rule_id);

    const json j = {
      {         "_s", "DeviceAllowed" },
      {       "id", id },
      { "attributes", attributes },
      { "rule_match", rule_match },
      {  "rule_id", rule_id }
    };

    qbIPCBroadcastJSON(j);
    return;
  }

  void Daemon::DeviceBlocked(uint32_t id,
			     const std::map<std::string,std::string>& attributes,
			     bool rule_match,
			     uint32_t rule_id)
  {
    logger->debug("DeviceBlocked: id={}, rule_match={}, rule_id={}",
		  id, rule_match, rule_id);

    const json j = {
      {         "_s", "DeviceBlocked" },
      {       "id", id },
      { "attributes", attributes },
      { "rule_match", rule_match },
      {  "rule_id", rule_id }
    };

    qbIPCBroadcastJSON(j);
    return;
  }

  void Daemon::DeviceRejected(uint32_t id,
			      const std::map<std::string,std::string>& attributes,
			      bool rule_match,
			      uint32_t rule_id)
  {
    logger->debug("DeviceRejected: id={}, rule_match={}, rule_id={}",
		  id, rule_match, rule_id);

    const json j = {
      {         "_s", "DeviceRejected" },
      {       "id", id },
      { "attributes", attributes },
      { "rule_match", rule_match },
      {  "rule_id", rule_id }
    };

    qbIPCBroadcastJSON(j);
    return;
  }

  void Daemon::dmHookDeviceInserted(Pointer<Device> device)
  {
    /*
     * Since we search for a matching rule later, we have to generate a port
     * specific rule here.
     */
    Pointer<Rule> device_rule = device->getDeviceRule(/*include_port=*/true);
    Pointer<Rule> matched_rule = _ruleset.getFirstMatchingRule(device_rule);

    std::map<std::string,std::string> attributes;
    
    attributes["name"] = device_rule->getName();
    attributes["vendor_id"] = device_rule->getDeviceID().getVendorID();
    attributes["product_id"] = device_rule->getDeviceID().getProductID();
    attributes["serial"] = device_rule->getSerial();
    attributes["hash"] = device_rule->getHash();

    DeviceInserted(device_rule->getRuleID(),
		   attributes,
		   device_rule->attributeWithInterface().values(),
		   matched_rule->isImplicit() ? false : true,
		   matched_rule->getRuleID());

    switch(matched_rule->getTarget()) {
    case Rule::Target::Allow:
      allowDevice(device_rule->getRuleID(), matched_rule);
      break;
    case Rule::Target::Block:
      blockDevice(device_rule->getRuleID(), matched_rule);
      break;
    case Rule::Target::Reject:
      rejectDevice(device_rule->getRuleID(), matched_rule);
      break;
    default:
      throw std::runtime_error("BUG: Wrong matched_rule target");
    }

    matched_rule->updateMetaDataCounters(/*applied=*/true);

    return;
  }

  void Daemon::dmHookDevicePresent(Pointer<Device> device)
  {
    /*
     * Since we search for a matching rule later, we have to generate a port
     * specific rule here.
     */
    Pointer<Rule> device_rule = device->getDeviceRule(/*include_port=*/true);
    std::map<std::string,std::string> attributes;

    attributes["name"] = device_rule->getName();
    attributes["vendor_id"] = device_rule->getDeviceID().getVendorID();
    attributes["product_id"] = device_rule->getDeviceID().getProductID();
    attributes["serial"] = device_rule->getSerial();
    attributes["hash"] = device_rule->getHash();

    const PresentDevicePolicy policy = \
      device->isController() ? _present_controller_policy : _present_device_policy;

    Rule::Target target = Rule::Target::Invalid;
    Pointer<Rule> matched_rule = nullptr;

    switch (policy) {
    case PresentDevicePolicy::Allow:
      target = Rule::Target::Allow;
      break;
    case PresentDevicePolicy::Block:
      target = Rule::Target::Block;
      break;
    case PresentDevicePolicy::Reject:
      target = Rule::Target::Reject;
      break;
    case PresentDevicePolicy::Keep:
      target = device->getTarget();
      break;
    case PresentDevicePolicy::ApplyPolicy:
      matched_rule = _ruleset.getFirstMatchingRule(device_rule);
      target = matched_rule->getTarget();
      break;
    }

    if (matched_rule == nullptr) {
      auto rule = makePointer<Rule>();
      rule->setTarget(target);
      matched_rule = rule;
    }

    switch(target) {
    case Rule::Target::Allow:
      allowDevice(device_rule->getRuleID(), matched_rule);
      break;
    case Rule::Target::Block:
      blockDevice(device_rule->getRuleID(), matched_rule);
      break;
    case Rule::Target::Reject:
      rejectDevice(device_rule->getRuleID(), matched_rule);
      break;
    default:
      throw std::runtime_error("BUG: Wrong matched_rule target");
    }

    matched_rule->updateMetaDataCounters(/*applied=*/true);

    DevicePresent(device_rule->getRuleID(),
		  attributes,
		  device_rule->attributeWithInterface().values(),
		  target);
    return;
  }

  void Daemon::dmHookDeviceRemoved(Pointer<Device> device)
  {
    /* We don't care about ports here, use the default */
    Pointer<Rule> device_rule = device->getDeviceRule();

    std::map<std::string,std::string> attributes;
    
    attributes["name"] = device_rule->getName();
    attributes["vendor_id"] = device_rule->getDeviceID().getVendorID();
    attributes["product_id"] = device_rule->getDeviceID().getProductID();
    attributes["serial"] = device_rule->getSerial();
    attributes["hash"] = device_rule->getHash();

    DeviceRemoved(device_rule->getRuleID(), attributes);
    return;
  }

  void Daemon::dmHookDeviceAllowed(Pointer<Device> device)
  {
    return;
  }

  void Daemon::dmHookDeviceBlocked(Pointer<Device> device)
  {
    return;
  }

  void Daemon::dmHookDeviceRejected(Pointer<Device> device)
  {
    return;
  }

  uint32_t Daemon::dmHookAssignID()
  {
    return assignID();
  }

  int32_t Daemon::qbSignalHandlerFn(int32_t signal, void *arg)
  {
    qb_loop_t *qb_loop = (qb_loop_t *)arg;
    logger->debug("Stopping main loop from signal handler");
    qb_loop_stop(qb_loop);

    if (signal == SIGSYS) {
      logger->warn("Stopped due to SIGSYS: A system call was used which is not whitelisted.");
    }

    return QB_FALSE;
  }

  Daemon::PresentDevicePolicy Daemon::presentDevicePolicyFromString(const String& policy_string)
  {
    const std::vector<std::pair<String,Daemon::PresentDevicePolicy> > policy_ttable = {
      { "allow", PresentDevicePolicy::Allow },
      { "block", PresentDevicePolicy::Block },
      { "reject", PresentDevicePolicy::Reject },
      { "keep", PresentDevicePolicy::Keep },
      { "apply-policy", PresentDevicePolicy::ApplyPolicy }
    };

    for (auto ttable_entry : policy_ttable) {
      if (ttable_entry.first == policy_string) {
	return ttable_entry.second;
      }
    }

    throw std::runtime_error("Invalid present device policy string");
  }

  void Daemon::allowDevice(uint32_t id, Pointer<const Rule> matched_rule)
  {
    Pointer<Device> device = _dm->allowDevice(id);
    /*
     * We don't care about include_port value here, the generated rule isn't
     * used for policy evaluation.
     */
    Pointer<Rule> device_rule = device->getDeviceRule();

    std::map<std::string,std::string> attributes;
    
    attributes["name"] = device_rule->getName();
    attributes["vendor_id"] = device_rule->getDeviceID().getVendorID();
    attributes["product_id"] = device_rule->getDeviceID().getProductID();

    DeviceAllowed(device_rule->getRuleID(),
		  attributes,
		  (matched_rule->getRuleID() != Rule::DefaultID),
		  matched_rule->getRuleID());
    return;
  }

  void Daemon::blockDevice(uint32_t id, Pointer<const Rule> matched_rule)
  {
    Pointer<Device> device = _dm->blockDevice(id);
    /*
     * We don't care about include_port value here, the generated rule isn't
     * used for policy evaluation.
     */
    Pointer<Rule> device_rule = device->getDeviceRule();

    std::map<std::string,std::string> attributes;
    
    attributes["name"] = device_rule->getName();
    attributes["vendor_id"] = device_rule->getDeviceID().getVendorID();
    attributes["product_id"] = device_rule->getDeviceID().getProductID();

    DeviceBlocked(device_rule->getRuleID(),
		  attributes,
		  (matched_rule->getRuleID() != Rule::DefaultID),
		  matched_rule->getRuleID());
    return;
  }

  void Daemon::rejectDevice(uint32_t id, Pointer<const Rule> matched_rule)
  {
    Pointer<Device> device = _dm->rejectDevice(id);
    /*
     * We don't care about include_port value here, the generated rule isn't
     * used for policy evaluation.
     */
    Pointer<Rule> device_rule = device->getDeviceRule();

    std::map<std::string,std::string> attributes;
    
    attributes["name"] = device_rule->getName();
    attributes["vendor_id"] = device_rule->getDeviceID().getVendorID();
    attributes["product_id"] = device_rule->getDeviceID().getProductID();

    DeviceRejected(device_rule->getRuleID(),
		   attributes,
		   (matched_rule->getRuleID() != Rule::DefaultID),
		   matched_rule->getRuleID());
    return;
  }

  const std::vector<Rule> Daemon::listDevices(const std::string& query)
  {
    std::vector<Rule> device_rules;
    const Rule query_rule = Rule::fromString(query);

    for (auto const& device : _dm->getDeviceList(query_rule)) {
      device_rules.push_back(*device->getDeviceRule());
    }

    return device_rules;
  }

  Pointer<const Rule> Daemon::upsertDeviceRule(uint32_t id, Rule::Target target, uint32_t timeout_sec)
  {
    Pointer<Device> device = _dm->getDevice(id);

    bool with_port = true && _device_rules_with_port;
    bool with_parent_hash = true;

    /*
     * Generate a port specific or agnostic rule depending on the target
     */
    switch(target) {
      case Rule::Target::Allow:
        with_port = true && with_port;
        with_parent_hash = true;
        break;
      case Rule::Target::Block:
        /*
         * Block the device using a port agnostic rule, so that the same device
         * inserted in a different port is still blocked. Note that allowDevice
         * generates a port specific rule and the same device won't be allowed
         * when inserted in a different port.
         */
        with_port = false;
        with_parent_hash = false;
        break;
      case Rule::Target::Reject:
        /*
         * Reject the device using a port agnostic port. When we explicitly
         * reject a device, we don't want to reject it again when the same
         * device is inserted in a different port.
         */
        with_port = false;
        with_parent_hash = false;
        break;
      default:
        throw std::runtime_error("upsertDeviceRule: invalid device rule target");
    }

    /* Generate a match rule for upsert */
    Pointer<Rule> match_rule = device->getDeviceRule(false, false);
    match_rule->setTarget(Rule::Target::Match);
    const String match_spec = match_rule->toString();

    /* Generate new device rule */
    Pointer<Rule> device_rule = device->getDeviceRule(with_port, with_parent_hash); 
    device_rule->setTarget(target);
    const String rule_spec = device_rule->toString();

    /* Upsert */
    const uint32_t rule_id = upsertRule(match_spec, rule_spec, /*parent_insensitive=*/true);

    return _ruleset.getRule(rule_id);
  }

  void Daemon::addIPCAllowedUID(uid_t uid)
  {
    /* TODO */
  }

  void Daemon::addIPCAllowedGID(gid_t gid)
  {
    /* TODO */
  }

  void Daemon::addIPCAllowedUID(const String& username)
  {
    char string_buffer[4096];
    struct passwd pw, *pwptr = nullptr;

    if (getpwnam_r(username.c_str(), &pw,
		   string_buffer, sizeof string_buffer, &pwptr) != 0) {
      throw std::runtime_error("cannot lookup username");
    }

    addIPCAllowedUID(pw.pw_uid);
  }

  void Daemon::addIPCAllowedGID(const String& groupname)
  {
    char string_buffer[4096];
    struct group gr, *grptr = nullptr;

    if (getgrnam_r(groupname.c_str(), &gr,
		   string_buffer, sizeof string_buffer, &grptr) != 0) {
      throw std::runtime_error("cannot lookup groupname");
    }

    addIPCAllowedGID(gr.gr_gid);
  }
} /* namespace usbguard */
