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
#include "USB.hpp"
#include "Common/ByteOrder.hpp"
#include "Common/Utility.hpp"
#include "LoggerPrivate.hpp"
#include <stdexcept>
#include <iostream>
#include <algorithm>

namespace usbguard {
  USBDeviceID::USBDeviceID()
  {
  }

  USBDeviceID::USBDeviceID(const String& vendor_id, const String& product_id)
  {
    checkDeviceID(vendor_id, product_id);
    setVendorID(vendor_id);
    setProductID(product_id);
  }

  USBDeviceID::USBDeviceID(const USBDeviceID& rhs)
  {
    _vendor_id = rhs._vendor_id;
    _product_id = rhs._product_id;
  }

  void USBDeviceID::checkDeviceID(const String& vendor_id, const String& product_id)
  {
    if (vendor_id.empty() || vendor_id == "*") {
      /* product id must be empty or "*" */
      if (!product_id.empty() && product_id != "*") {
        throw std::runtime_error("Invalid USB device id format");
      }
    }
    if (vendor_id.size() > USB_VID_STRING_MAX_LENGTH) {
      throw std::runtime_error("Vendor ID string size out of range");
    }
    if (product_id.size() > USB_PID_STRING_MAX_LENGTH) {
      throw std::runtime_error("Product ID string size out of range");
    }
  }

  void USBDeviceID::setVendorID(const String& vendor_id)
  {
    checkDeviceID(vendor_id, _product_id);
    _vendor_id = vendor_id;
  }

  void USBDeviceID::setProductID(const String& product_id)
  {
    checkDeviceID(_vendor_id, product_id);
    _product_id = product_id;
  }

  const String& USBDeviceID::getVendorID() const
  {
    return _vendor_id;
  }

  const String& USBDeviceID::getProductID() const
  {
    return _product_id;
  }

  String USBDeviceID::toRuleString() const
  {
    return _vendor_id + ":" + _product_id;
  }

  String USBDeviceID::toString() const
  {
    return toRuleString();
  }

  bool USBDeviceID::isSubsetOf(const USBDeviceID& rhs) const
  {
    if (rhs._vendor_id.empty() || rhs._vendor_id == "*") {
      return true;
    }
    else if (_vendor_id != rhs._vendor_id) {
      return false;
    }

    if (rhs._product_id.empty() || rhs._product_id == "*") {
      return true;
    }
    else if (_product_id != rhs._product_id) {
      return false;
    }

    return true;
  }

  template<>
  bool Predicates::isSubsetOf(const USBDeviceID& source, const USBDeviceID& target)
  {
    return source.isSubsetOf(target);
  }

  USBInterfaceType::USBInterfaceType()
  {
    _bClass = 0;
    _bSubClass = 0;
    _bProtocol = 0;
    _mask = 0;
    return;
  }

  USBInterfaceType::USBInterfaceType(uint8_t bClass, uint8_t bSubClass, uint8_t bProtocol, uint8_t mask)
  {
    _bClass = bClass;
    _bSubClass = bSubClass;
    _bProtocol = bProtocol;
    _mask = mask;

    return;
  }

  USBInterfaceType::USBInterfaceType(const USBInterfaceDescriptor& descriptor, uint8_t mask)
  {
    _bClass = descriptor.bInterfaceClass;
    _bSubClass = descriptor.bInterfaceSubClass;
    _bProtocol = descriptor.bInterfaceProtocol;
    _mask = mask;
    return;
  }

  USBInterfaceType::USBInterfaceType(const std::string& type_string)
  {
    std::vector<std::string> tokens;
    tokenizeString(type_string, tokens, ":", /*trim_empty=*/false);

    _bClass = 0;
    _bSubClass = 0;
    _bProtocol = 0;
    _mask = 0;

    if (tokens.size() != 3) {
      throw std::runtime_error("Invalid type_string");
    }

    if (tokens[0].size() != 2) {
      throw std::runtime_error("Invalid type_string");
    }
    else {
      _bClass = stringToNumber<uint8_t>(tokens[0], 16);
      _mask |= MatchClass;
    }

    if (tokens[1] != "*") {
      if (tokens[1].size() != 2) {
	throw std::runtime_error("Invalid type_string");
      }
      else {
	_bSubClass = stringToNumber<uint8_t>(tokens[1], 16);
	_mask |= MatchSubClass;
      }
    }

    if (tokens[2] != "*") {
      if (tokens[2].size() != 2) {
	throw std::runtime_error("Invalid type_string");
      }
      else {
	_bProtocol = stringToNumber<uint8_t>(tokens[2], 16);
	_mask |= MatchProtocol;
      }
    }

    if (!(_mask == (MatchAll) ||
	  _mask == (MatchClass|MatchSubClass) ||
	  _mask == (MatchClass))) {
      throw std::runtime_error("Invalid type_string");
    }

    return;
  }

  bool USBInterfaceType::operator==(const USBInterfaceType& rhs) const
  {
    return (_bClass == rhs._bClass &&
	    _bSubClass == rhs._bSubClass &&
	    _bProtocol == rhs._bProtocol &&
	    _mask == rhs._mask);
  }

  bool USBInterfaceType::appliesTo(const USBInterfaceType& rhs) const
  {
    if (_mask & MatchClass) {
      if (_bClass != rhs._bClass) {
	return false;
      }
    }
    if (_mask & MatchSubClass) {
      if (_bSubClass != rhs._bSubClass) {
	return false;
      }
    }
    if (_mask & MatchProtocol) {
      if (_bProtocol != rhs._bProtocol) {
	return false;
      }
    }
    return true;
  }

  template<>
  bool Predicates::isSubsetOf(const USBInterfaceType& source, const USBInterfaceType& target)
  {
    return source.appliesTo(target);
  }

  const String USBInterfaceType::typeString() const
  {
    return USBInterfaceType::typeString(_bClass, _bSubClass, _bProtocol, _mask);
  }

  const String USBInterfaceType::toRuleString() const
  {
    return typeString();
  }

  const String USBInterfaceType::typeString(uint8_t bClass, uint8_t bSubClass, uint8_t bProtocol, uint8_t mask)
  {
    String type_string("");

    if (mask & MatchClass) {
      type_string.append(numberToString(bClass, "", 16, 2, '0') + ":");

      if (mask & MatchSubClass) {
	type_string.append(numberToString(bSubClass, "", 16, 2, '0') + ":");

	if (mask & MatchProtocol) {
	  type_string.append(numberToString(bProtocol, "", 16, 2, '0'));
	}
	else {
	  type_string.append("*");
	}
      }
      else {
	type_string.append("*:*");
      }
    }
    else {
      throw std::runtime_error("BUG: cannot create type string, invalid mask");
    }

    return type_string;
  }

  void USBParseDeviceDescriptor(USBDescriptorParser* parser, const USBDescriptor* descriptor_raw, USBDescriptor* descriptor_out)
  {
    const USBDeviceDescriptor* device_raw = reinterpret_cast<const USBDeviceDescriptor*>(descriptor_raw);
    USBDeviceDescriptor* device_out = reinterpret_cast<USBDeviceDescriptor*>(descriptor_out);

    /* Copy 1:1 */
    *device_out = *device_raw;

    /* Convert multibyte field to host endianness */
    device_out->bcdUSB = busEndianToHost(device_raw->bcdUSB);
    device_out->idVendor = busEndianToHost(device_raw->idVendor);
    device_out->idProduct = busEndianToHost(device_raw->idProduct);
    device_out->bcdDevice = busEndianToHost(device_raw->bcdDevice);

    return;
  }

  void USBParseConfigurationDescriptor(USBDescriptorParser* parser, const USBDescriptor* descriptor_raw, USBDescriptor* descriptor_out)
  {
    const USBConfigurationDescriptor* configuration_raw = reinterpret_cast<const USBConfigurationDescriptor*>(descriptor_raw);
    USBConfigurationDescriptor* configuration_out = reinterpret_cast<USBConfigurationDescriptor*>(descriptor_out);

    /* Copy 1:1 */
    *configuration_out = *configuration_raw;

    /* Convert multibyte field to host endianness */
    configuration_out->wTotalLength = busEndianToHost(configuration_raw->wTotalLength);

    return;
  }

  void USBParseInterfaceDescriptor(USBDescriptorParser* parser, const USBDescriptor* descriptor_raw, USBDescriptor* descriptor_out)
  {
    const USBInterfaceDescriptor* interface_raw = reinterpret_cast<const USBInterfaceDescriptor*>(descriptor_raw);
    USBInterfaceDescriptor* interface_out = reinterpret_cast<USBInterfaceDescriptor*>(descriptor_out);

    /* Copy 1:1 */
    *interface_out = *interface_raw;

    return;
  }

  void USBParseEndpointDescriptor(USBDescriptorParser* parser, const USBDescriptor* descriptor_raw, USBDescriptor* descriptor_out)
  {
    const USBEndpointDescriptor* endpoint_raw = reinterpret_cast<const USBEndpointDescriptor*>(descriptor_raw);
    USBEndpointDescriptor* endpoint_out = reinterpret_cast<USBEndpointDescriptor*>(descriptor_out);

    *endpoint_out = *endpoint_raw;
    endpoint_out->wMaxPacketSize = busEndianToHost(endpoint_raw->wMaxPacketSize);

    return;
  }

  void USBParseAudioEndpointDescriptor(USBDescriptorParser* parser, const USBDescriptor* descriptor_raw, USBDescriptor* descriptor_out)
  {
    const USBAudioEndpointDescriptor* endpoint_raw = reinterpret_cast<const USBAudioEndpointDescriptor*>(descriptor_raw);
    USBAudioEndpointDescriptor* endpoint_out = reinterpret_cast<USBAudioEndpointDescriptor*>(descriptor_out);

    *endpoint_out = *endpoint_raw;
    endpoint_out->wMaxPacketSize = busEndianToHost(endpoint_raw->wMaxPacketSize);

    return;
  }

  const std::vector<USBDescriptorParser::Handler>* USBDescriptorParser::getDescriptorTypeHandler(uint8_t bDescriptorType) const
  {
    const auto it = _handler_map.find(bDescriptorType);
    if (it == _handler_map.end()) {
      return nullptr;
    }
    return &it->second;
  }

  bool USBDescriptorParser::getDescriptorTypeHandler(const USBDescriptorHeader& header, const USBDescriptorParser::Handler*& handler) const
  {
    const auto handlers = getDescriptorTypeHandler(header.bDescriptorType);

    if (handlers == nullptr) {
      return false;
    }

    handler = nullptr;

    for (auto& candidate_handler : *handlers) {
      /*
       * Fixed size descriptor handler. Save pointer to the handler
       * and short circuit the loop
       */
      if (candidate_handler.bLengthExpected == header.bLength) {
        handler = &candidate_handler;
        break;
      }
      /*
       * Variable size descriptor handler. Save pointer to the handler
       * and continue searching as there might be a matching fixed size
       * handler.
       */
      if (candidate_handler.bLengthExpected == 0) {
        handler = &candidate_handler;
      }
    }

    return true;
  }

  size_t USBDescriptorParser::parse(std::istream& stream)
  {
    size_t size_processed = 0;

    while (stream.good()) {
      USBDescriptorHeader header;
      stream.read(reinterpret_cast<char*>(&header), sizeof header);

      if (stream.gcount() != sizeof header) {
        /*
         * If we read nothing and the stream if at EOF, just break
         * the loop and return normally. Checking the sanity of the
         * parsed descriptor data is up to the higher layers.
         */
        if (stream.gcount() == 0 && stream.eof()) {
          break;
        }
        /*
         * Otherwise throw an exception because there's unknown garbage
         * in the stream which cannot be a valid USB descriptor.
         */
        else {
          throw std::runtime_error("Cannot parse descriptor data: partial read while reading header data");
        }
      }

      /*
       * The bLength value has to be at least 2, because that is the size of the USB
       * descriptor header.
       */
      if (header.bLength < sizeof(USBDescriptorHeader)) {
        throw std::runtime_error("Invalid descriptor data: bLength is less than the size of the header");
      }

      /*
       * Let's try to read the rest of the descriptor data before we start looking
       * for the descriptor type handler. If there's not enough data in the stream,
       * then there's no point for searching for the handler.
       */
      USBDescriptor descriptor;

      descriptor.bHeader = header;
      memset(&descriptor.bDescriptorData, 0, sizeof descriptor.bDescriptorData);

      /*
       * We read (bLength - header_size) amount of data here because the bLength value
       * counts in the size of the header too and we already read it from the stream.
       */
      stream.read(reinterpret_cast<char*>(&descriptor.bDescriptorData), header.bLength - sizeof(USBDescriptorHeader));

      if (stream.gcount() != (std::streamsize)(header.bLength - sizeof(USBDescriptorHeader))) {
        throw std::runtime_error("Invalid descriptor data: bLength value larger than the amount of available data");
      }

      /*
       * Find handler for the descriptor type & length.
       */
      const Handler *handler = nullptr;

      if (getDescriptorTypeHandler(header, handler)) {
        if (handler == nullptr) {
          throw std::runtime_error("Invalid descriptor data: invalid combination of bDescriptorType and bLength values");
        }
      }
      else {
        const USBDescriptorHeader header_unknown = {
          .bLength = header.bLength,
          .bDescriptorType = USB_DESCRIPTOR_TYPE_UNKNOWN
        };

        (void)getDescriptorTypeHandler(header_unknown, handler);
        /*
         * If there's not even an unknown descriptor type handler, just
         * ignore it and count in the length. Until we implement
         * support for all descriptor types as defined by all used USB
         * specifications, we cannot do anything else here...
         */
        if (handler == nullptr) {
          size_processed += header.bLength;
          continue;
        }
      }

      if (handler == nullptr) {
        throw std::runtime_error("BUG: No descriptor type handler selected in USBDescriptorParser::parse");
      }

      USBDescriptor descriptor_parsed;
      descriptor_parsed.bHeader = header;
      memset(&descriptor_parsed.bDescriptorData, 0, sizeof descriptor_parsed.bDescriptorData);

      if (handler->parser) {
        handler->parser(this, &descriptor, &descriptor_parsed);
      }
      if (handler->callback) {
        handler->callback(this, &descriptor_parsed);
      }

      setDescriptor(header.bDescriptorType, descriptor_parsed);
      size_processed += header.bLength;
    }

    return size_processed;
  }

  void USBDescriptorParser::setHandler(uint8_t bDescriptorType, uint8_t bLengthExpected, ParserFunction parser, CallbackFunction callback)
  {
    auto& handlers = _handler_map[bDescriptorType];

    Handler handler;
    handler.parser = parser;
    handler.callback = callback;
    handler.bLengthExpected = bLengthExpected;

    handlers.push_back(handler);
  }

  const std::vector<USBDescriptor>* USBDescriptorParser::getDescriptor(uint8_t bDescriptorType) const
  {
    auto const& it = _dstate_map.find(bDescriptorType);
    if (it == _dstate_map.end()) {
      return nullptr;
    }
    return &it->second;
  }

  void USBDescriptorParser::setDescriptor(uint8_t bDescriptorType, const USBDescriptor& descriptor)
  {
    auto& descriptors = _dstate_map[bDescriptorType];
    bool set = false;
    for (auto& stored_descriptor : descriptors) {
      if (stored_descriptor.bHeader.bLength == descriptor.bHeader.bLength) {
        stored_descriptor = descriptor;
        set = true;
      }
    }
    if (!set) {
      descriptors.push_back(descriptor);
    }
    /*
     * Count in the descriptor no matter if we overwrote one or not.
     * We are counting all occurences of a descriptor type.
     */
    ++_count_map[bDescriptorType];
  }

  void USBDescriptorParser::delDescriptor(uint8_t bDescriptorType)
  {
    _dstate_map.erase(bDescriptorType);
  }

  bool USBDescriptorParser::haveDescriptor(uint8_t bDescriptorType) const
  {
    return _dstate_map.count(bDescriptorType) > 0;
  }

  const std::vector<std::pair<uint8_t,size_t>> USBDescriptorParser::getDescriptorCounts() const
  {
    std::vector<std::pair<uint8_t,size_t>> counts;

    for (auto const& kv : _count_map) {
      counts.push_back(std::make_pair(kv.first, kv.second));
    }

    std::sort(counts.begin(), counts.end());

    return counts;
  }

} /* namespace usbguard */
