#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class IPCServerProcess : public pgl::Process
  {
    public:
    IPCServerProcess();
    ~IPCServerProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
