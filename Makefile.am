#######################################################################
##
## Makefile.am for the pool accounts plugin
##
#######################################################################

ACLOCAL_AMFLAGS = -I m4 -I src

# no-write-strings is done because lcmaps_log uses "char *" instead
# of "const char *", causing newer compilers to freak
AM_CFLAGS = \
        -Werror \
	-Wall \
	-Wp,-D_FORTIFY_SOURCE=2 \
        $(LCMAPS_CFLAGS)

AM_CXXFLAGS = \
        $(LCMAPS_CFLAGS) \
        -Wno-write-strings \
        -Werror \
	-Wall \
	-Wp,-D_FORTIFY_SOURCE=2 \
        $(CXX0X_CFLAGS)

EXTRA_DIST = bootstrap lcmaps-plugins-pool-accounts.spec

plugindir = $(MODULEDIR)
plugin_LTLIBRARIES = \
        liblcmaps_pool_accounts.la
liblcmaps_pool_accounts_la_SOURCES = \
	src/lcmaps_pool_accounts.c

liblcmaps_pool_accounts_la_LDFLAGS = -avoid-version

install-data-hook:
	( \
	cd $(DESTDIR)$(plugindir); \
	for mod in pool_accounts; do \
	    rm -f lcmaps_$$mod.mod; \
	    ln -s liblcmaps_$$mod.so.0.0.0 lcmaps_$$mod.mod; \
	done \
	)

