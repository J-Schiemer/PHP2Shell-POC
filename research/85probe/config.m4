PHP_ARG_ENABLE([p2s85probe],
  [whether to enable the p2s85probe lab extension],
  [AS_HELP_STRING([--enable-p2s85probe], [Enable p2s85probe])],
  [no])

if test "$PHP_P2S85PROBE" != "no"; then
  PHP_NEW_EXTENSION([p2s85probe], [p2s85probe.c], [$ext_shared])
fi
