#pragma once
#include <pgl.hpp>

namespace usbguard
{
  class ConfigProcess : public pgl::Process
  {
    public:
    ConfigProcess();
    ~ConfigProcess();

    int main(int argc, char *argv[]);

    private:
  };
} /* namespace usbguard */
