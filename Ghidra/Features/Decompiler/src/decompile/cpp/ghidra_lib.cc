#include "ghidra_process.hh"
#include <streambuf>
#include <iostream>
#include <vector>
#include <cstring>

using namespace ghidra;
using namespace std;

extern "C" {

typedef int (*ReadCallback)(void* handle, char* buf, int len);
typedef int (*WriteCallback)(void* handle, const char* buf, int len);

class JavaStreambuf : public std::streambuf {
    void* handle;
    ReadCallback read_cb;
    WriteCallback write_cb;
    char in_buf[4096];
    char out_buf[4096];

protected:
    virtual int underflow() {
        if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
        int n = read_cb(handle, in_buf, sizeof(in_buf));
        if (n <= 0) return traits_type::eof();
        setg(in_buf, in_buf, in_buf + n);
        return traits_type::to_int_type(*gptr());
    }

    virtual int overflow(int c) {
        if (c != traits_type::eof()) {
            *pptr() = c;
            pbump(1);
        }
        if (flush_buffer() == -1) return traits_type::eof();
        return c == traits_type::eof() ? traits_type::not_eof(c) : c;
    }

    virtual int sync() {
        return flush_buffer();
    }

    int flush_buffer() {
        int n = pptr() - pbase();
        if (n > 0) {
            if (write_cb(handle, out_buf, n) != n) return -1;
            pbump(-n);
        }
        return 0;
    }

public:
    JavaStreambuf(void* h, ReadCallback r, WriteCallback w) : handle(h), read_cb(r), write_cb(w) {
        setg(in_buf, in_buf, in_buf);
        setp(out_buf, out_buf + sizeof(out_buf));
    }
    
    ~JavaStreambuf() {
        sync();
    }
};

void* ghidra_init() {
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    return (void*)1;
}

int ghidra_run_loop(void* handle, ReadCallback read_cb, WriteCallback write_cb) {
    JavaStreambuf buf(handle, read_cb, write_cb);
    istream sin(&buf);
    ostream sout(&buf);
    
    int status = 0;
    while(status == 0) {
        if (sin.peek() == EOF) {
            break;
        }
        status = GhidraCapability::readCommand(sin, sout);
        sout.flush();
    }
    return status;
}

void ghidra_cleanup(void* handle) {
    GhidraCapability::shutDown();
}

}
