#include "ConfigProcess.hpp"
#include "Common/JSON.hpp"
#include <stdlib.h>

namespace usbguard
{
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
    "IPCAllowedGroups"
  };

  ConfigProcess::ConfigProcess()
    : _config(G_config_known_names)
  {
  }

  ConfigProcess::~ConfigProcess()
  {
  }

  int ConfigProcess::main(int argc, char *argv[])
  {
    int ret = EXIT_FAILURE;

    _config.open(USBGUARD_CONFIG_PATH);

    while(true) {
      if (messageBusWait() != 1) {
        continue;
      }

      std::string json_string;
      const pid_t peer_pid = messageBusRecv(-1, json_string);

      processMessage(peer_pid, json_string);
    }

    _config.close();

    return ret;
  }

  void ConfigProcess::processMessage(const pid_t peer_pid, const std::string& json_string)
  {
    const json message = json_string;

    if (message["op"] == "get") {
      const std::string key = message["key"];
      processConfigGet(peer_pid, key);
    }
    else if (message["op"] == "set") {
      const std::string key = message["key"];
      const std::string val = message["val"];
      processConfigSet(peer_pid, key, val);
    }

    return;
  }

  void ConfigProcess::processConfigGet(const pid_t peer_pid, const std::string& key)
  {
    const std::string& val = _config.getSettingValue(key);
    messageBusSend(peer_pid, val);
    return;
  }

  void ConfigProcess::processConfigSet(const pid_t peer_pid, const std::string& key,
      const std::string& val)
  {
    _config.setSettingValue(key, val);
    return;
  }

} /* namespace usbguard */
