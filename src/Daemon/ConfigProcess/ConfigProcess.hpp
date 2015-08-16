#pragma once
#include <pgl.hpp>
#include "ConfigFile.hpp"

#ifndef USBGUARD_CONFIG_PATH
#define USBGUARD_CONFIG_PATH "/etc/usbguard/usbguard-daemon.conf"
#endif

namespace usbguard
{
  class ConfigProcess : public pgl::Process
  {
    public:
      ConfigProcess();
      ~ConfigProcess();

      int main(int argc, char *argv[]);

    protected:
      void processMessage(const pid_t peer_pid, const std::string& json_string);
      void processConfigGet(const pid_t peer_pid, const std::string& key);
      void processConfigSet(const pid_t peer_pid, const std::string& key, const std::string& val);

    private:
      ConfigFile _config;
  };
} /* namespace usbguard */

