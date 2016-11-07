## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

EXTRA_DIST = squirrel.conf 

install-data-am:
	test -e $(DESTDIR)$(sysconfdir) || \
		$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	test -e $(DESTDIR)$(sysconfdir)/squirrel.conf || \
		$(INSTALL_DATA) -m 600 $(top_srcdir)/etc/squirrel.conf \
		$(DESTDIR)$(sysconfdir)/squirrel.conf
