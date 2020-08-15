# SPDX-License-Identifier: GPL-2.0-only
# (c) William Fonkou Tambe

%C%_run_SOURCES =
%C%_run_LDADD = \
	%D%/nrun.o \
	%D%/libsim.a \
	$(SIM_COMMON_LIBS)

noinst_PROGRAMS += %D%/run
