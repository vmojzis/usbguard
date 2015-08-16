#include "ConfigProcess/ConfigProcess.hpp"
#include "PolicyProcess/PolicyProcess.hpp"
#include "IPCServerProcess/IPCServerProcess.hpp"
#include "RuleSysIOProcess/RuleSysIOProcess.hpp"
#include "USBControlProcess/USBControlProcess.hpp"
#include "USBEventsProcess/USBEventsProcess.hpp"
#include "USBMonitorProcess/USBMonitorProcess.hpp"

#include <pgl.hpp>
#include <stdlib.h>

using namespace usbguard;

int main(int argc, char *argv[])
{
  int ret = EXIT_FAILURE;
  pgl::Group group(argc, argv);

  try {
    group.addProcess<ConfigProcess>("config");
    group.addProcess<PolicyProcess>("policy");
    group.addProcess<IPCServerProcess>("ipc-server");
    group.addProcess<RuleSysIOProcess>("rule-sysio");
    group.addProcess<USBControlProcess>("usb-control");
    group.addProcess<USBEventsProcess>("usb-events");
    group.addProcess<USBMonitorProcess>("usb-monitor");

    ret = group.run();
  }
  catch(const std::exception& ex) {
    PGL_LOG() << "Exception caught: " << ex.what();
  }
  catch(...) {
    PGL_LOG() << "Unexpected exception caught. Aborting.";
    abort();
  }

  return ret;
}

