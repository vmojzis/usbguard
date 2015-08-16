#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class USBMonitorProcess : public pgl::Process
  {
    public:
    USBMonitorProcess();
    ~USBMonitorProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
