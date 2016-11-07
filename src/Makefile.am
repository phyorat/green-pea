## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = squirrel

squirrel_SOURCES = squirrel.c squirrel.h \
bounds.h \
checksum.h \
debug.c debug.h \
decode.c decode.h \
fatal.h \
ipv6_port.h \
generators.h \
log.c log.h \
log_text.c log_text.h \
map.c map.h \
mstring.c mstring.h \
parser.c parser.h \
pcap_pkthdr32.h \
plugbase.c plugbase.h \
rules.h \
sf_types.h \
spooler.c spooler.h \
strlcatu.c strlcatu.h \
strlcpyu.c strlcpyu.h \
sf_protocols.h \
timersub.h \
twofish.c twofish.h \
unified2.h \
util.c util.h

squirrel_LDADD = output-plugins/libspo.a \
input-plugins/libspi.a \
sfutil/libsfutil.a

SUBDIRS = sfutil output-plugins input-plugins

AM_CPPFLAGS = -Isfutil
