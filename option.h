#include <getopt.h>

struct option long_options[] = {
        {"help",         no_argument,       NULL, 'h'},
        {"echo",         no_argument,       NULL, 'E'},
        {"timestamp",    no_argument,       NULL, 'T'},
        {"mask",         no_argument,       NULL, 'M'},
        {"info",         no_argument,       NULL, 'I'},
        {"source",       no_argument,       NULL, 'S'},
        {"time",         no_argument,       NULL, 'X'},
        {"unreach",      no_argument,       NULL, 'U'},
        {"redirect",     required_argument, NULL, 'R'},
        {"parameter",    no_argument,       NULL, 'P'},
        {"paramptr",     required_argument, NULL, 'p'},
        {"code",         required_argument, NULL, 'e'},
        {"src",          required_argument, NULL, 's'},
        {"dst",          required_argument, NULL, 'd'},
        {"count",        required_argument, NULL, 'c'},
        {"iface",        required_argument, NULL, 'i'},
        {"mtu",          required_argument, NULL, 'm'},
        {"verbose",      no_argument,       NULL, 'v'},
        {"extraverbose", no_argument,       NULL, 'x'},
        {"ttl",          required_argument, NULL, 't'},
        {"id",           required_argument, NULL, 'n'},
        {"fakeproto",    required_argument, NULL, 'f'},
        {"fakettl",      required_argument, NULL, 'k'},
        {"fakeid",       required_argument, NULL, 'a'},
        {"fakelength",   required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
};

