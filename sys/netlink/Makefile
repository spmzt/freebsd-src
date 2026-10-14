# Makefile for the snl(3) parsers generated from the YANG modules in specs/

.include <src.lua.mk>

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

YANL_SCRIPT?=	${.CURDIR}/../tools/yanl/yanl.lua
YANL=		${LUA} ${YANL_SCRIPT} -p ${.CURDIR}/specs

GENERATED=	netlink_snl_route_parsers.h

# The parsers are emitted in this order: a binding may only use the
# parsers of the bindings before it.
BINDINGS.netlink_snl_route_parsers.h=	freebsd-rtnetlink-route-snl	\
					freebsd-rtnetlink-link-snl	\
					freebsd-rtnetlink-neigh-snl	\
					freebsd-rtnetlink-addr-snl	\
					freebsd-rtnetlink-nexthop-snl

all:
	@echo "make snl only"

snl: ${GENERATED}

# We slap a .PHONY on the script so that we regenerate every single time
# rather than tracking its internal dependencies.
${YANL_SCRIPT}: .PHONY

.for _h in ${GENERATED}
${_h}: ${YANL_SCRIPT} ${BINDINGS.${_h}:S|^|specs/|:S|$|.yang|}
	${YANL} -o ${.TARGET} ${BINDINGS.${_h}}
.endfor
