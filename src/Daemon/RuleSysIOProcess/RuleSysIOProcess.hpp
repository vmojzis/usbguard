#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class RuleSysIOProcess : public pgl::Process
  {
    public:
    RuleSysIOProcess();
    ~RuleSysIOProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
