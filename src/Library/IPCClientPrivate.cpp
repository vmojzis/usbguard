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
#include "IPCClientPrivate.hpp"
#include "IPCPrivate.hpp"
#include "LoggerPrivate.hpp"

#include <sys/poll.h>
#include <sys/eventfd.h>

namespace usbguard
{
  static int32_t qbPollEventFn(int32_t fd, int32_t revents, void *data)
  {
    return 0;
  }

  static int32_t qbIPCMessageProcessFn(int32_t fd, int32_t revents, void *data)
  {
    IPCClientPrivate *client = static_cast<IPCClientPrivate*>(data);
    client->processEvent();
    return 0;
  }

  IPCClientPrivate::IPCClientPrivate(IPCClient& p_instance, bool connected)
    : _p_instance(p_instance),
      _thread(this, &IPCClientPrivate::thread)
  {
    _qb_conn = nullptr;
    _qb_conn_fd = -1;
    _wakeup_fd = eventfd(0, 0);
    _qb_loop = qb_loop_create();
    qb_loop_poll_add(_qb_loop, QB_LOOP_HIGH, _wakeup_fd, POLLIN, NULL, qbPollEventFn);
    _thread.start();

    if (connected) {
      try {
        connect();
      }
      catch(...) {
        destruct();
        throw;
      }
    }
  }

  void IPCClientPrivate::destruct()
  {
    stop();
    qb_loop_poll_del(_qb_loop, _wakeup_fd);
    close(_wakeup_fd);
    qb_loop_destroy(_qb_loop);
  }

  IPCClientPrivate::~IPCClientPrivate()
  {
    disconnect();
    destruct();
  }

  void IPCClientPrivate::connect()
  {
    _qb_conn = qb_ipcc_connect("usbguard", 1<<20);

    if (_qb_conn == nullptr) {
      throw IPCException(IPCException::ConnectionError, "IPC Connection not established");
    }

    qb_ipcc_fd_get(_qb_conn, &_qb_conn_fd);

    if (_qb_conn_fd < 0) {
      qb_ipcc_disconnect(_qb_conn);
      _qb_conn = nullptr;
      _qb_conn_fd = -1;
      throw IPCException(IPCException::ConnectionError, "Bad file descriptor");
    }

    qb_loop_poll_add(_qb_loop, QB_LOOP_HIGH, _qb_conn_fd, POLLIN, this, qbIPCMessageProcessFn);
    _p_instance.IPCConnected();
  }

  void IPCClientPrivate::disconnect(bool exception_initiated, const IPCException& exception)
  {
    if (_qb_conn != nullptr && _qb_conn_fd != -1) {
      qb_loop_poll_del(_qb_loop, _qb_conn_fd);
      qb_ipcc_disconnect(_qb_conn);
      _qb_conn = nullptr;
      _qb_conn_fd = -1;
      _p_instance.IPCDisconnected(/*exception_initiated=*/true, exception);
    }
  }

  void IPCClientPrivate::disconnect()
  {
    const IPCException empty_exception;
    disconnect(/*exception_initiated=*/false, empty_exception);
  }

  bool IPCClientPrivate::isConnected() const
  {
    return _qb_conn_fd != -1;
  }

  void IPCClientPrivate::wait()
  {
    _thread.wait();
  }

  void IPCClientPrivate::thread()
  {
    qb_loop_run(_qb_loop);
  }

  void IPCClientPrivate::wakeup()
  {
    const uint64_t one = 1;
    (void)write(_wakeup_fd, &one, sizeof one);
  }

  void IPCClientPrivate::stop()
  {
    _thread.stop(/*do_wait=*/false);
    qb_loop_stop(_qb_loop);
    wakeup();
    _thread.wait();
  }

  IPC::MessagePointer IPCClientPrivate::qbIPCSendRecvMessage(const IPC::MessagePointer& message)
  {
    if (!isConnected()) {
      throw IPCException(IPCException::ConnectionError, "Not connected");
    }

    std::string payload;
    message->SerializeToString(&payload);

    struct qb_ipc_request_header hdr;
    hdr.id = QB_IPC_MSG_USER_START + IPC::messageTypeNameToNumber(message->GetTypeName());
    hdr.size = sizeof hdr + payload.size();

    struct iovec iov[2];
    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof hdr;
    iov[1].iov_base = (void *)payload.data();
    iov[1].iov_len = payload.size();

    const uint64_t id = 0;

    /* Lock the return value slot map */
    std::unique_lock<std::mutex> return_map_lock(_return_map_mutex);

    /*
     * Create the promise and future objects.
     * The promise will be fullfiled by the message
     * processing handlers after they process
     * a reply from the server.
     */
    auto& promise = _return_map[id];
    auto future = promise.get_future();

    qb_ipcc_sendv(_qb_conn, iov, 2);

    /* 
     * Unlock the return value map so that the message
     * processing handler aren't blocked.
     */
    return_map_lock.unlock();

    /* Wait for some time for the reply to be received */
    const std::chrono::milliseconds timeout_ms(5*1000); /* TODO: make this configurable */
    const bool timed_out = \
      future.wait_for(timeout_ms) == std::future_status::timeout;

    MessagePointer response;

    if (!timed_out) {
      response = future.get();
    }

    /* Remove the slot from the return value slot map */
    return_map_lock.lock();
    _return_map.erase(id);
    return_map_lock.unlock();

    if (timed_out) {
      throw IPCException(IPCException::TransientError, "Timed out while waiting for IPC reply");
    }

    /*
     * We might have caused an exception. Check whether
     * that's the case and if true, throw it here.
     */
    if (IPC::isExceptionMessage(response)) {
      throw IPC::IPCExceptionFromMessage(response);
    }

    return response;
  }

  void IPCClientPrivate::processReceiveEvent()
  {
    try {
      const std::string buffer = receive();
      process(buffer);
    }
    catch(const IPCException& ex) {
      logger->error("IPC: Disconnecting because of an IPC exception: event_id={}, code={}", ex.requestID(), ex.codeAsString());
      disconnect(/*exception_initiated=*/true, ex);
    }
    catch(const std::exception& ex) {
      const IPCException ipc_exception(IPCException::ReasonCode::InternalError, ex.what());
      logger->error("IPC: Disconnecting because of an exception: {}", ex.what());
      disconnect(/*exception_initiated=*/true, ipc_exception);
    }
    catch(...) {
      const IPCException ipc_exception(IPCException::ReasonCode::InternalError, "BUG: Unknown exception in IPCPrivate::processEvent");
      logger->error("BUG: IPC: Disconnecting because of an unknown exception.");
      disconnect(/*exception_initiated=*/true, ipc_exception);
    }
  }

  std::string IPCClientPrivate::receive()
  {
    const size_t buffer_size_max = 1<<20;
    std::string buffer(buffer_size_max);

    const ssize_t recv_size = \
      qb_ipcc_event_recv(_qb_conn, &buffer[0], /*msg_len=*/buffer_size, /*ms_timeout=*/500);

    if (recv_size < 0) {
      disconnect();
      throw IPCException(IPCException::ProtocolError, "Receive error");
    }
    if (recv_size < (ssize_t)sizeof(struct qb_ipc_response_header)) {
      disconnect();
      throw IPCException(IPCException::ProtocolError, "Message too small");
    }

    buffer.resize((size_t)recv_size);

    return buffer;
  }

  void IPCClientPrivate::process(const std::string& buffer)
  {
    const struct qb_ipc_response_header *hdr = \
      (const struct qb_ipc_response_header *)buffer.data();

    if (hdr->size != recv_size) {
      disconnect();
      throw IPCException(IPCException::ProtocolError, "Invalid size in IPC header");
    }
    if (hdr->id < QB_IPC_MSG_USER_START) {
      disconnect();
      throw IPCException(IPCException::ProtocolError, "Invalid type in IPC header");
    }

    const uint32_t payload_type = hdr->id - QB_IPC_MSG_USER_START;
    const std::string payload = buffer.substr(sizeof(struct qb_ipc_response_header));

    handleIPCPayload(payload_type, payload);
  }

  void IPCClientPrivate::handleIPCPayload(const uint32_t payload_type, const std::string& payload)
  {
    try {
      const auto& handler = _handlers.at(payload_type);
      const auto message = handler.payloadToMessage(payload);
      (void)handler.run(message);
    }
    catch(...) {
      throw std::runtime_error("Unknown IPC payload type");
    }
  }

#if 0
  void IPCClientPrivate::processReturnValue(const json& jobj)
  {
    std::unique_lock<std::mutex> lock(_rv_map_mutex);
    const uint64_t id = jobj["_i"];
    auto const& it = _rv_map.find(id);

    if (it == _rv_map.end()) {
      return;
    }

    auto& promise = it->second;
    promise.set_value(jobj);

    return;
  }
#endif

} /* namespace usbguard */
