
inc_HEADERS += \
	p11-kit/deprecated.h \
	p11-kit/iter.h \
	p11-kit/p11-kit.h \
	p11-kit/pin.h \
	p11-kit/remote.h \
	p11-kit/uri.h \
	$(NULL)

MODULE_SRCS = \
	p11-kit/util.c \
	p11-kit/conf.c p11-kit/conf.h \
	p11-kit/iter.c \
	p11-kit/log.c p11-kit/log.h \
	p11-kit/modules.c p11-kit/modules.h \
	p11-kit/pkcs11.h \
	p11-kit/pin.c \
	p11-kit/pkcs11.h \
	p11-kit/private.h \
	p11-kit/proxy.c p11-kit/proxy.h \
	p11-kit/messages.c \
	p11-kit/rpc-transport.c p11-kit/rpc.h \
	p11-kit/rpc-message.c p11-kit/rpc-message.h \
	p11-kit/rpc-client.c p11-kit/rpc-server.c \
	p11-kit/uri.c \
	p11-kit/virtual.c p11-kit/virtual.h \
	$(inc_HEADERS)

lib_LTLIBRARIES += \
	libp11-kit.la

libp11_kit_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(p11_system_config_file)"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(p11_system_config_modules)"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(p11_package_config_modules)"\" \
	-DP11_USER_CONFIG_FILE=\""$(p11_user_config_file)"\" \
	-DP11_USER_CONFIG_MODULES=\""$(p11_user_config_modules)"\" \
	-DP11_MODULE_PATH=\""$(p11_module_path)"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

libp11_kit_la_LDFLAGS = \
	-no-undefined \
	-version-info $(P11KIT_LT_RELEASE) \
	-export-symbols-regex '^C_GetFunctionList|^p11_kit_'

libp11_kit_la_SOURCES = $(MODULE_SRCS)

libp11_kit_la_LIBADD = \
	libp11-common.la \
	libp11-library.la \
	$(LIBFFI_LIBS) \
	$(LTLIBINTL) \
	$(NULL)

noinst_LTLIBRARIES += \
	libp11-kit-testable.la

libp11_kit_testable_la_LDFLAGS = -no-undefined
libp11_kit_testable_la_SOURCES = $(MODULE_SRCS)
libp11_kit_testable_la_LIBADD = $(libp11_kit_la_LIBADD)

if OS_WIN32

libp11_kit_testable_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/system-pkcs11.conf"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/system-modules/win32"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/package-modules/win32"\" \
	-DP11_USER_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/user-pkcs11.conf"\" \
	-DP11_USER_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/user-modules/win32"\" \
	-DP11_MODULE_PATH=\""$(abs_top_builddir)/.libs"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

else

libp11_kit_testable_la_CFLAGS = \
	-DP11_SYSTEM_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/system-pkcs11.conf"\" \
	-DP11_SYSTEM_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/system-modules"\" \
	-DP11_PACKAGE_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/package-modules"\" \
	-DP11_USER_CONFIG_FILE=\""$(abs_top_srcdir)/p11-kit/fixtures/user-pkcs11.conf"\" \
	-DP11_USER_CONFIG_MODULES=\""$(abs_top_srcdir)/p11-kit/fixtures/user-modules"\" \
	-DP11_MODULE_PATH=\""$(abs_top_builddir)/.libs"\" \
	$(LIBFFI_CFLAGS) \
	$(NULL)

# Proxy module is actually same as library, so install a link
install-exec-hook:
	$(LN_S) -f `readlink $(DESTDIR)$(libdir)/libp11-kit.{so,dylib}` $(DESTDIR)$(libdir)/p11-kit-proxy.so
	$(MKDIR_P) $(DESTDIR)$(p11_package_config_modules)

endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = p11-kit/p11-kit-1.pc

exampledir = $(p11_system_config)
example_DATA = p11-kit/pkcs11.conf.example

EXTRA_DIST += \
	p11-kit/p11-kit-1.pc.in \
	p11-kit/pkcs11.conf.example.in \
	p11-kit/docs.h \
	$(NULL)

bin_PROGRAMS += p11-kit/p11-kit

p11_kit_p11_kit_SOURCES = \
	p11-kit/lists.c \
	p11-kit/p11-kit.c \
	$(NULL)

p11_kit_p11_kit_LDADD = \
	libp11-kit.la \
	libp11-tool.la \
	libp11-common.la \
	$(LTLIBINTL) \
	$(NULL)

private_PROGRAMS += p11-kit-remote

p11_kit_remote_SOURCES = \
	p11-kit/remote.c \
	$(NULL)

p11_kit_remote_LDADD = \
	libp11-tool.la \
	libp11-common.la \
	libp11-kit.la \
	$(NULL)

# Tests ----------------------------------------------------------------

p11_kit_LIBS = \
	libp11-kit-testable.la \
	libp11-test.la \
	libp11-common.la \
	$(LTLIBINTL)

CHECK_PROGS += \
	test-progname \
	test-util \
	test-conf \
	test-uri \
	test-pin \
	test-init \
	test-modules \
	test-deprecated \
	test-proxy \
	test-iter \
	test-rpc \
	$(NULL)

test_conf_SOURCES = p11-kit/test-conf.c
test_conf_LDADD = $(p11_kit_LIBS)

test_deprecated_SOURCES = p11-kit/test-deprecated.c
test_deprecated_LDADD = $(p11_kit_LIBS)

test_init_SOURCES = p11-kit/test-init.c
test_init_LDADD = $(p11_kit_LIBS)

test_iter_SOURCES = p11-kit/test-iter.c
test_iter_LDADD = $(p11_kit_LIBS)

test_modules_SOURCES = p11-kit/test-modules.c
test_modules_LDADD = $(p11_kit_LIBS)

test_pin_SOURCES = p11-kit/test-pin.c
test_pin_LDADD = $(p11_kit_LIBS)

test_progname_SOURCES = p11-kit/test-progname.c
test_progname_LDADD = $(p11_kit_LIBS)

test_proxy_SOURCES = p11-kit/test-proxy.c
test_proxy_LDADD = $(p11_kit_LIBS)

test_rpc_SOURCES = p11-kit/test-rpc.c
test_rpc_LDADD = $(p11_kit_LIBS)

test_uri_SOURCES = p11-kit/test-uri.c
test_uri_LDADD = $(p11_kit_LIBS)

test_util_SOURCES = p11-kit/test-util.c
test_util_LDADD = $(p11_kit_LIBS)

noinst_PROGRAMS += \
	print-messages \
	frob-setuid

print_messages_SOURCES = p11-kit/print-messages.c
print_messages_LDADD = $(p11_kit_LIBS)

frob_setuid_SOURCES = p11-kit/frob-setuid.c
frob_setuid_LDADD = $(p11_kit_LIBS)

if WITH_FFI

CHECK_PROGS += \
	test-virtual \
	test-managed \
	test-log \
	test-transport \
	$(NULL)

test_log_SOURCES = p11-kit/test-log.c
test_log_LDADD = $(p11_kit_LIBS)

test_managed_SOURCES = p11-kit/test-managed.c
test_managed_LDADD = $(p11_kit_LIBS)

test_transport_SOURCES = p11-kit/test-transport.c
test_transport_LDADD = $(p11_kit_LIBS)

test_virtual_SOURCES = p11-kit/test-virtual.c
test_virtual_LDADD = $(p11_kit_LIBS)

endif

noinst_LTLIBRARIES += \
	mock-one.la \
	mock-two.la \
	mock-three.la \
	mock-four.la

mock_one_la_SOURCES = p11-kit/mock-module-ep.c
mock_one_la_LIBADD = libp11-test.la libp11-common.la
mock_one_la_LDFLAGS = \
	-module -avoid-version -rpath /nowhere \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

mock_two_la_SOURCES = p11-kit/mock-module-ep2.c
mock_two_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_two_la_LIBADD = $(mock_one_la_LIBADD)

mock_three_la_SOURCES = $(mock_one_la_SOURCES)
mock_three_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_three_la_LIBADD = $(mock_one_la_LIBADD)

mock_four_la_SOURCES = $(mock_one_la_SOURCES)
mock_four_la_LDFLAGS = $(mock_one_la_LDFLAGS)
mock_four_la_LIBADD = $(mock_one_la_LIBADD)

EXTRA_DIST += \
	p11-kit/fixtures \
	p11-kit/test-mock.c \
	$(NULL)
