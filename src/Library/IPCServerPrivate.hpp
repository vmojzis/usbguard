//
// Copyright (C) 2016 Red Hat, Inc.
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
#include "IPCServer.hpp"
#include "IPCPrivate.hpp"
#include "Common/Thread.hpp"
#include "Common/JSON.hpp"

#include <map>
#include <mutex>
#include <future>

#include <qb/qbipcs.h>
#include <qb/qbloop.h>

#include <Devices.pb.h>
#include <Policy.pb.h>
#include <Exception.pb.h>

namespace usbguard {
  class IPCServerPrivate
  {
    using MessageHandler = IPC::MessageHandler<IPCServerPrivate>;

  public:
    IPCServerPrivate(IPCServer& p_instance);
    ~IPCServerPrivate();

  private:
    void initIPC();
    void finiIPC();

    void thread();
    void wakeup();
    void stop();
    void destruct();

    static int32_t qbIPCConnectionAcceptFn(qb_ipcs_connection_t *, uid_t, gid_t);
    static void qbIPCConnectionCreatedFn(qb_ipcs_connection_t *);
    static void qbIPCConnectionDestroyedFn(qb_ipcs_connection_t *);
    static int32_t qbIPCConnectionClosedFn(qb_ipcs_connection_t *);
    static int32_t qbIPCMessageProcessFn(qb_ipcs_connection_t *, void *, size_t);

    static int32_t qbIPCJobAdd(enum qb_loop_priority p, void *data, qb_loop_job_dispatch_fn fn);
    static int32_t qbIPCDispatchAdd(enum qb_loop_priority p, int32_t fd, int32_t evts, void *data, qb_ipcs_dispatch_fn_t fn);
    static int32_t qbIPCDispatchMod(enum qb_loop_priority p, int32_t fd, int32_t evts, void *data, qb_ipcs_dispatch_fn_t fn);
    static int32_t qbIPCDispatchDel(int32_t fd);

    bool qbIPCConnectionAllowed(uid_t uid, gid_t gid);
    bool authenticateIPCConnectionDAC(uid_t uid, gid_t gid);

    static void qbIPCSendMessage(qb_ipcs_connection_t *qb_conn, const std::unique_ptr<google::protobuf::Message>& message);
    void qbIPCBroadcastData(const struct iovec *iov, size_t iov_len);
    void qbIPCBroadcastMessage(const std::unique_ptr<google::protobuf::Message>& message);
    std::unique_ptr<google::protobuf::Message> handleIPCPayload(const uint32_t payload_type, const std::string& payload);
 
    template<class T>
    void registerHandler(MessageHandler::HandlerType method)
    {
      const uint32_t type_number = messageTypeNameToNumber(T::default_instance->GetTypeName());
      _handlers[type_number] = MessageHandler::create<T>(*this, method);
    }

    std::unique_ptr<IPC::listRulesResponse> handleListRules(const std::unique_ptr<IPC::listRulesRequest>& request);

    IPCServer& _p_instance;

    qb_loop_t *_qb_loop;
    qb_ipcs_service_t *_qb_service;
    int _wakeup_fd;

    std::vector<uid_t> _allowed_uids;
    std::vector<gid_t> _allowed_gids;

    Thread<IPCServerPrivate> _thread;

    std::unordered_map<uint32_t, MessageHandler> _handlers;
  };

} /* namespace usbguard */
