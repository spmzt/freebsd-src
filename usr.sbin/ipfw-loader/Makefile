.include <src.opts.mk>

PROG=	ipfw-loader
SRCS=	main.c resolver.c fw-interface.c
SRCS+=	fw-parse.y token.l y.tab.h
MK_MAN=	no

LIBADD+=util

# convert to HAS_TESTS or test:
#FLAGS!=	./check-features.sh
test: all
	python -m unittest -v tests/parser.py

.include <bsd.prog.mk>

CWARNFLAGS+= -Wno-cast-align
