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

#include "IPC.hpp"
#include "Typedefs.hpp"

#include <memory>
#include <google/protobuf/message.h>

namespace usbguard
{
  namespace IPC
  {
    uint32_t messageTypeNameToNumber(const std::string& name);
    const std::string& messageTypeNameFromNumber(uint32_t number);

    using MessageType = google::protobuf::Message;
    using MessagePointer = std::unique_ptr<MessageType>;

    MessagePointer IPCExceptionToMessage(const IPCException& exception);
    IPCException IPCExceptionFromMessage(const MessagePointer& message);

    bool isExceptionMessage(const MessagePointer& message);
 
    template<class C>
    class MessageHandler
    {
      public:
        using HandlerType = MessagePointer(C::*)(const MessagePointer&);

        MessageHandler(C& c, HandlerType method, const MessageType* factory)
          : _instance(c),
            _method(method),
            _message_factory(factory)
        {
        }

        MessageHandler(const MessageHandler& rhs)
          : _instance(rhs._instance),
            _method(rhs._method),
            _message_factory(rhs._factory)
        {
        }

        MessagePointer payloadToMessage(const std::string& payload) const
        {
          MessagePointer message(_message_factory->New());
          message->ParseFromString(payload);
          return message;
        }

        MessagePointer run(const MessagePointer& message) const
        {
          if (message->GetTypeName() != _message_factory->GetTypeName()) {
            throw std::runtime_error("BUG: Incompatible message type passed to handler");
          }

          return (_instance.*_method)(message);
        }

        template<class ProtobufType>
        static MessageHandler *create(C& c, HandlerType method)
        {
          return new MessageHandler(c, method, ProtobufType::default_instance());
        }

      private:
        C& _instance;
        HandlerType _method;
        const MessageType *_message_factory;
   };
  }
} /* namespace usbguard */
