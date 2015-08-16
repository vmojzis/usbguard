#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class PolicyProcess : public pgl::Process
  {
    public:
    PolicyProcess();
    ~PolicyProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
