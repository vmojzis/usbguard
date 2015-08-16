#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class USBEventsProcess : public pgl::Process
  {
    public:
    USBEventsProcess();
    ~USBEventsProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
