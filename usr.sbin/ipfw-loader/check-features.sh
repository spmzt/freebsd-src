#!/bin/sh

#
#  Copyright (c) 2007-2026 Yandex, LLC. All rights reserved.
#

FLAGS=

cc -xc - 2>/dev/null << EOF
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ip_compat.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>

int
main()
{
    enum ipfw_opcodes test = O_SETIPPREC;
}
EOF

if [ $? -eq 0 ]; then
	FLAGS="$FLAGS -DHAS_SETIPPREC"
fi

rm -f a.out

cc -xc - 2>/dev/null << EOF
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ip_compat.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>

int
main()
{
    enum ipfw_opcodes test = O_REASS;
}
EOF

if [ $? -eq 0 ]; then
	FLAGS="$FLAGS -DHAS_REASS"
fi

rm -f a.out

echo $FLAGS
