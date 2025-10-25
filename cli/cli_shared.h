#pragma once

#include "xdp_labeling.h"

#define PROG_NAME "xdp-labeling"
#define ERRBUF_SZ 256
#define DEFAULT_BPF_OBJECT XDP_LABELING_DEFAULT_OBJECT
#define PIN_DIR XDP_LABELING_PIN_ROOT_DEFAULT

#ifndef __unused
#define __unused __attribute__((unused))
#endif
