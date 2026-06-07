#include "hdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <arpa/inet.h>

Mac::Mac(const std::string& r){
        std::string s;
        for(char ch:r){
                if((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
                        s += ch;
        }
        int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if(res != Size){
                fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
                return;
        }
}

Mac Mac::get_mac(const std::string& iface){
        Mac result;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(fd<0) return result;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);

        if(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0){
                memcpy(result.mac, ifr.ifr_hwaddr.sa_data, 6);
        }

        close(fd);
        return result;
}

Ip::Ip(const std::string r){
        unsigned int a, b, c, d;
        int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        if(res != Size){
                fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
                return;
        }
        ip = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip Ip::get_ip(const std::string& iface){
        Ip result;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(fd<0) return result;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);

        if(ioctl(fd, SIOCGIFADDR, &ifr) == 0){
                struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
                result.ip = ntohl(sin->sin_addr.s_addr);
        }

        close(fd);
        return result;
}

Parser::Parser(const uint8_t* data, size_t len) : data(data), len(len) {}

bool Parser::require(size_t n) const{
        return off <= len && n <= len - off;
}

bool Parser::skip(size_t n){
	if(!require(n)) return false;
	off += n;
	return true;
}

bool Parser::read_u8(uint8_t& v){
	if(!require(1)) return false;
	v = data[off];
	off += 1;
	return true;
}

bool Parser::read_u16(uint16_t& v){
	if(!require(2)) return false;
	v = ((uint16_t)data[off] << 8) | data[off + 1];
	off += 2;
	return true;
}

bool Parser::read_u24(uint32_t& v){
	if(!require(3)) return false;
	v = ((uint32_t)data[off] << 16) |
	    ((uint32_t)data[off + 1] << 8) |
	    data[off + 2];
	off += 3;
	return true;
}

bool Parser::read_bytes(const uint8_t*& p, size_t n){
	if(!require(n)) return false;
	p = data + off;
	off += n;
	return true;
}

bool extract_sni(const uint8_t* data, size_t len, std::string& sni){
	Parser p(data, len);

	uint8_t content_type;
	uint16_t version;
	uint16_t record_len;

	if(!p.read_u8(content_type)) return false;
	if(!p.read_u16(version)) return false;
	if(!p.read_u16(record_len)) return false;

	if(content_type != 0x16) return false; // Handshake
	if(!p.require(record_len)) return false;

	size_t record_end = p.off + record_len;
	uint8_t handshake_type;
	uint32_t handshake_len;

	if(!p.read_u8(handshake_type)) return false;
	if(!p.read_u24(handshake_len)) return false;

	if(handshake_type != 0x01) return false; // ClientHello

	size_t handshake_end = p.off + handshake_len;
	if(handshake_end > record_end) return false;

	if(!p.skip(2)) return false;  // legacy_version
	if(!p.skip(32)) return false; // random

	uint8_t session_id_len;
	if(!p.read_u8(session_id_len)) return false;
	if(!p.skip(session_id_len)) return false;

	uint16_t cipher_suites_len;
	if(!p.read_u16(cipher_suites_len)) return false;
	if(!p.skip(cipher_suites_len)) return false;

	uint8_t compression_methods_len;
	if(!p.read_u8(compression_methods_len)) return false;
	if(!p.skip(compression_methods_len)) return false;

	uint16_t extensions_len;
	if(!p.read_u16(extensions_len)) return false;

	size_t extensions_end = p.off + extensions_len;
	if(extensions_end > handshake_end || extensions_end > len) return false;

	while(p.off + 4 <= extensions_end){
		uint16_t ext_type;
		uint16_t ext_len;

		if(!p.read_u16(ext_type)) return false;
		if(!p.read_u16(ext_len)) return false;

		if(p.off + ext_len > extensions_end) return false;

		if(ext_type == 0x0000){
			Parser sni_parser(data + p.off, ext_len);

			uint16_t list_len;
			if(!sni_parser.read_u16(list_len)) return false;

			size_t list_end = sni_parser.off + list_len;
			if(list_end > sni_parser.len) return false;

			while(sni_parser.off + 3 <= list_end){
				uint8_t name_type;
				uint16_t name_len;

				if(!sni_parser.read_u8(name_type)) return false;
				if(!sni_parser.read_u16(name_len)) return false;

				if(sni_parser.off + name_len > list_end) return false;

				if(name_type == 0){
					const uint8_t* name;
					if (!sni_parser.read_bytes(name, name_len)) return false;

					sni.assign((const char*)name, name_len);
					return true;
				}

				if(!sni_parser.skip(name_len)) return false;
			}
		}

		if(!p.skip(ext_len)) return false;
	}

	return false;
}
