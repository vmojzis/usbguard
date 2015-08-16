#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class USBControlProcess : public pgl::Process
  {
    public:
    USBControlProcess();
    ~USBControlProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
