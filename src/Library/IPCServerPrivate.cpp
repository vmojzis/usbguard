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
#include "IPCServerPrivate.hpp"
#include "IPCPrivate.hpp"
#include "LoggerPrivate.hpp"

#include <sys/poll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

namespace usbguard
{
  static qb_loop *G_qb_loop = nullptr;

  IPCServerPrivate::IPCServerPrivate(IPCServer& p_instance)
    : _p_instance(p_instance),
      _thread(this, &IPCServerPrivate::thread)
  {
    if (G_qb_loop != nullptr) {
      throw std::runtime_error("BUG: Only one instance of IPCServer per process allowed");
    }

    G_qb_loop = _qb_loop = qb_loop_create();

    if (_qb_loop == nullptr) {
      throw std::runtime_error("Failed to create qb_loop instance");
    }

    try {
      initIPC();
    }
    catch(...) {
      qb_loop_destroy(_qb_loop);
      G_qb_loop = nullptr;
    }

    //registerHandler<IPC::listRulesRequest>(&IPCServerPrivate::handleListRules);
  }

  void IPCServerPrivate::initIPC()
  {
    static struct qb_ipcs_service_handlers service_handlers = {
      IPCServerPrivate::qbIPCConnectionAcceptFn,
      IPCServerPrivate::qbIPCConnectionCreatedFn,
      IPCServerPrivate::qbIPCMessageProcessFn,
      IPCServerPrivate::qbIPCConnectionClosedFn,
      IPCServerPrivate::qbIPCConnectionDestroyedFn
    };

    _qb_service = qb_ipcs_create("usbguard", 0,
				 QB_IPC_NATIVE, &service_handlers);

    if (_qb_service == nullptr) {
      throw std::runtime_error("Cannot create qb_service instance");
    }

    qb_ipcs_service_context_set(_qb_service, this);

    static struct qb_ipcs_poll_handlers poll_handlers = {
      IPCServerPrivate::qbIPCJobAdd,
      IPCServerPrivate::qbIPCDispatchAdd,
      IPCServerPrivate::qbIPCDispatchMod,
      IPCServerPrivate::qbIPCDispatchDel
    };

    qb_ipcs_poll_handlers_set(_qb_service, &poll_handlers);

    const auto rc = qb_ipcs_run(_qb_service);

    if (rc != 0) {
      logger->error("Cannot start the IPC server: qb_ipcs_run failed: {}", strerror((int)-rc));
      throw std::runtime_error("IPC server error");
    }
  }

  void IPCServerPrivate::finiIPC()
  {
    qb_ipcs_destroy(_qb_service);
  }

  IPCServerPrivate::~IPCServerPrivate()
  {
  }

  void IPCServerPrivate::thread()
  {
    qb_loop_run(_qb_loop);
  }

  void IPCServerPrivate::wakeup()
  {
    const uint64_t one = 1;
    (void)write(_wakeup_fd, &one, sizeof one);
  }

  void IPCServerPrivate::stop()
  {
    _thread.stop(/*do_wait=*/false);
    qb_loop_stop(_qb_loop);
    wakeup();
    _thread.wait();
  }

  void IPCServerPrivate::destruct()
  {
    stop();
    qb_loop_poll_del(_qb_loop, _wakeup_fd);
    close(_wakeup_fd);
    qb_loop_destroy(_qb_loop);
  }

  void IPCServerPrivate::qbIPCConnectionCreatedFn(qb_ipcs_connection_t *conn)
  {
    logger->debug("Connection created");
  }

  void IPCServerPrivate::qbIPCConnectionDestroyedFn(qb_ipcs_connection_t *conn)
  {
    logger->debug("Connection destroyed");
  }

  int32_t IPCServerPrivate::qbIPCConnectionClosedFn(qb_ipcs_connection_t *conn)
  {
    logger->debug("Connection closed");
    return 0;
  }

  int32_t IPCServerPrivate::qbIPCJobAdd(enum qb_loop_priority p, void *data, qb_loop_job_dispatch_fn fn)
  {
    return qb_loop_job_add(G_qb_loop, p, data, fn);
  }

  int32_t IPCServerPrivate::qbIPCDispatchAdd(enum qb_loop_priority p, int32_t fd, int32_t evts,
				   void *data, qb_ipcs_dispatch_fn_t fn)
  {
    return qb_loop_poll_add(G_qb_loop, p, fd, evts, data, fn);
  }

  int32_t IPCServerPrivate::qbIPCDispatchMod(enum qb_loop_priority p, int32_t fd, int32_t evts,
				   void *data, qb_ipcs_dispatch_fn_t fn)
  {
    return qb_loop_poll_mod(G_qb_loop, p, fd, evts, data, fn);
  }

  int32_t IPCServerPrivate::qbIPCDispatchDel(int32_t fd)
  {
    return qb_loop_poll_del(G_qb_loop, fd);
  }

  int32_t IPCServerPrivate::qbIPCConnectionAcceptFn(qb_ipcs_connection_t *conn, uid_t uid, gid_t gid)
  {
    IPCServerPrivate* server = \
      static_cast<IPCServerPrivate*>(qb_ipcs_connection_service_context_get(conn));

    const bool auth = server->qbIPCConnectionAllowed(uid, gid);

    if (auth) {
      logger->debug("IPC Connection accepted. "
		    "Setting SHM permissions to uid={} gid={} mode=0660", uid, 0);
      qb_ipcs_connection_auth_set(conn, uid, 0, 0660);
      return 0;
    }
    else {
      logger->debug("IPC Connection rejected");
      return -1;
    }
  }

  bool IPCServerPrivate::qbIPCConnectionAllowed(uid_t uid, gid_t gid)
  {
    if (!_allowed_uids.empty() || !_allowed_gids.empty()) {
      logger->debug("Using DAC IPC ACL");
      logger->debug("Connection request from uid={} gid={}", uid, gid);
      return authenticateIPCConnectionDAC(uid, gid);
    }
    else {
      logger->debug("IPC authentication is turned off.");
      return true;
    }
  }

  void IPCServerPrivate::qbIPCSendMessage(qb_ipcs_connection_t *qb_conn, const std::unique_ptr<google::protobuf::Message>& message)
  {
    if (qb_conn == nullptr || message == nullptr) {
      throw std::runtime_error("BUG: qbIPCSendMessage: invalid argument");
    }

    std::string payload;
    message->SerializeToString(&payload);

    struct qb_ipc_response_header hdr;
    struct iovec iov[2];
 
    hdr.id = QB_IPC_MSG_USER_START + IPC::messageTypeNameToNumber(message->GetTypeName());
    hdr.size = sizeof hdr + payload.size();
    hdr.error = 0;

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof hdr;
    iov[1].iov_base = (void *)payload.data();
    iov[1].iov_len = payload.size();

    const size_t total_size = hdr.size;
    const ssize_t rc = qb_ipcs_event_sendv(qb_conn, iov, 2);

    if (rc < 0) {
      /* FIXME: There's no client identification value in the message */
      logger->warn("Failed to send data: {}", strerror((int)-rc));
    }
    else if ((size_t)rc != total_size) {
      /* FIXME: There's no client identification value in the message */
      logger->warn("Sent less data than expected. Expected {}, send {}.",
		   total_size, rc);
    }

    iov[0].iov_base = nullptr;
    iov[1].iov_base = nullptr;
  }

  int32_t IPCServerPrivate::qbIPCMessageProcessFn(qb_ipcs_connection_t *conn, void *data, size_t size)
  {
    if (size <= sizeof (struct qb_ipc_request_header)) {
      logger->error("Received invalid IPC data. Disconnecting from the client.");
      qb_ipcs_disconnect(conn);
      return 0;
    }
    if (size > 1<<20) {
      logger->error("Message too large. Disconnecting from the client.");
      qb_ipcs_disconnect(conn);
      return 0;
    }

    const struct qb_ipc_request_header * const hdr = \
      reinterpret_cast<const struct qb_ipc_request_header *>(data);

    if (size != (size_t)hdr->size) {
      logger->error("Invalid size in IPC header. Disconnecting from the client.");
      qb_ipcs_disconnect(conn);
      return 0;
    }
    if (hdr->id < QB_IPC_MSG_USER_START) {
      logger->error("Invalid type in IPC header. Disconnecting from the client.");
      qb_ipcs_disconnect(conn);
      return 0;
    }

    try {
      IPCServerPrivate * const server = \
        reinterpret_cast<IPCServerPrivate*>(qb_ipcs_connection_service_context_get(conn));

      const uint32_t payload_type = hdr->id - QB_IPC_MSG_USER_START;
      const char * const payload_data = reinterpret_cast<const char*>(data) + sizeof(struct qb_ipc_request_header);
      const size_t payload_size = size - sizeof(struct qb_ipc_request_header);
      const std::string payload(payload_data, payload_size);

      auto response = server->handleIPCPayload(payload_type, payload);

      if (response) {
        qbIPCSendMessage(conn, response);
      }
    }
    catch(const IPCException& ex) {
      logger->warn("IPCException: {}: {}", ex.codeAsString(), ex.what());
      qbIPCSendMessage(conn, IPC::IPCExceptionToMessage(ex));
      /* FALLTHROUGH */
    }
    catch(const std::out_of_range& ex) {
      logger->warn("Out-of-range exception caught while processing IPC message.");
      const IPCException ipc_exception(IPCException::NotFound, "Not found");
      qbIPCSendMessage(conn, IPC::IPCExceptionToMessage(ipc_exception));
      /* FALLTHROUGH */
    }
    catch(const std::exception& ex) {
      logger->error("Exception: {}", ex.what());
      logger->error("Invalid JSON object received. Disconnecting from the client.");
      qb_ipcs_disconnect(conn);
      /* FALLTHROUGH */
    }

    return 0;
  }

  void IPCServerPrivate::qbIPCBroadcastData(const struct iovec * const iov, const size_t iov_len)
  {
    auto qb_conn = qb_ipcs_connection_first_get(_qb_service);
    size_t total_size = 0;

    for (size_t i = 0; i < iov_len; ++i) {
      total_size += iov[i].iov_len;
    }

    logger->debug("Sending data of total size {}.", total_size);

    while (qb_conn != nullptr) {
      /* Send the data */
      const ssize_t rc = qb_ipcs_event_sendv(qb_conn, iov, iov_len);

      if (rc < 0) {
	/* FIXME: There's no client identification value in the message */
	logger->warn("Failed to send broadcast data to: {}", strerror((int)-rc));
      }
      else if ((size_t)rc != total_size) {
	/* FIXME: There's no client identification value in the message */
	logger->warn("Sent less data than expected to. Expected {}, send {}.",
		     total_size, rc);
      }
      
      /* Get the next connection */
      auto qb_conn_next = qb_ipcs_connection_next_get(_qb_service, qb_conn);
      qb_ipcs_connection_unref(qb_conn);
      qb_conn = qb_conn_next;
    }
  }

  void IPCServerPrivate::qbIPCBroadcastMessage(const std::unique_ptr<google::protobuf::Message>& message)
  {
    std::string payload;
    message->SerializeToString(&payload);

    struct qb_ipc_response_header hdr;
    hdr.id = QB_IPC_MSG_USER_START + IPC::messageTypeNameToNumber(message->GetTypeName());
    hdr.size = sizeof hdr + payload.size();
    hdr.error = 0;
    
    struct iovec iov[2];
    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof hdr;
    iov[1].iov_base = (void *)payload.data();
    iov[1].iov_len = payload.size();

    qbIPCBroadcastData(iov, 2);

    iov[0].iov_base = nullptr;
    iov[1].iov_base = nullptr;
  }

  bool IPCServerPrivate::authenticateIPCConnectionDAC(uid_t uid, gid_t gid)
  {
    /* Check for UID match */
    for (auto allowed_uid : _allowed_uids) {
      if (allowed_uid == uid) {
	logger->debug("uid {} is an allowed uid", uid);
	return true;
      }
    }

    /* Translate uid to username for group member matching */
    char pw_string_buffer[1024]; /* TODO: adjust size to max user/group name length */
    struct passwd pw, *pwptr = nullptr;
    bool check_group_membership = true;

    if (getpwuid_r(uid, &pw,
		   pw_string_buffer, sizeof pw_string_buffer, &pwptr) != 0) {
      logger->warn("Cannot lookup username for uid {}. Won't check group membership.", uid);
      check_group_membership = false;
    }

    /* Check for GID match or group member match */
    for (auto allowed_gid : _allowed_gids) {
      if (allowed_gid == gid) {
	logger->debug("gid {} is an allowed gid", gid);
	return true;
      }
      else if (check_group_membership) {
	char gr_string_buffer[3072];
	struct group gr, *grptr = nullptr;

	/* Fetch list of current group members of group with a gid == allowed_gid */
	if (getgrgid_r(allowed_gid, &gr,
		       gr_string_buffer, sizeof gr_string_buffer, &grptr) != 0) {
	  logger->warn("Cannot lookup groupname for gid {}. "
		       "Won't check group membership of uid {}", allowed_gid, uid);
	  continue;
	}

	/* Check for username match among group members */
	for (size_t i = 0; gr.gr_mem[i] != nullptr; ++i) {
	  if (strcmp(pw.pw_name, gr.gr_mem[i]) == 0) {
	    logger->debug("uid {} ({}) is a member of an allowed group with gid {} ({})",
			  uid, pw.pw_name, allowed_gid, gr.gr_name);
	    return true;
	  }
	}
      }
    } /* allowed gid loop */

    return false;
  }

  std::unique_ptr<google::protobuf::Message> IPCServerPrivate::handleIPCPayload(const uint32_t payload_type, const std::string& payload)
  {
    try {
      const auto& handler = _handlers.at(payload_type);
      const auto message = handler.payloadToMessage(payload);
      return handler.run(message);
    }
    catch(...) {
      throw std::runtime_error("Unknown IPC payload type");
    }
  }
} /* namespace usbguard */
