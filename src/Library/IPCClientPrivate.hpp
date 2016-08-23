//
// Copyright (C) 2015 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Authors: Daniel Kopecek <dkopecek@redhat.com>
//
#pragma once
#include <build-config.h>
#include "Typedefs.hpp"
#include "IPCClient.hpp"
#include "IPCPrivate.hpp"
#include "Common/Thread.hpp"
#include "Common/JSON.hpp"

#include <map>
#include <mutex>
#include <future>

#include <qb/qbipcc.h>
#include <qb/qbloop.h>

namespace usbguard {
  class IPCClientPrivate
  {
  public:
    IPCClientPrivate(IPCClient& p_instance, bool connected);
    ~IPCClientPrivate();

    void connect();
    void disconnect(bool exception_initiated, const IPCException& exception);
    void disconnect();
    bool isConnected() const;
    void wait();

#if 0
    uint32_t appendRule(const std::string& rule_spec, uint32_t parent_id, uint32_t timeout_sec);
    void removeRule(uint32_t id);
    const RuleSet listRules();

    void allowDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    void blockDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    void rejectDevice(uint32_t id, bool permanent, uint32_t timeout_sec);
    const std::vector<Rule> listDevices(const std::string& query);
#endif

  protected:
    void destruct();
    void thread();
    void wakeup();
    void stop();

    uint64_t acquireMessageID();
    void releaseMessageID(uint64_t id);

    IPC::MessagePointer qbIPCSendRecvJSON(const IPC::MessagePointer& message);

    void processReceiveEvent();
    std::string receive();
    void process(const std::string& buffer);
    void handleIPCPayload(uint32_t payload_type, const std::string& payload);

  private:
    IPCClient& _p_instance;

    qb_loop_t *_qb_loop;
    qb_ipcc_connection_t *_qb_conn;
    int _qb_fd;

    int _wakeup_fd;

    std::mutex _return_mutex;
    std::map<uint64_t, std::promise<IPC::MessagePointer>> _return_map;

    Thread<IPCClientPrivate> _thread;
    std::map<uint32_t, IPC::MessageHandler> _handlers;
  };
} /* namespace usbguard */
