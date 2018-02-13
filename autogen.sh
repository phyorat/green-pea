#!/bin/sh
# Run this to generate all the initial makefiles, etc.
if which libtoolize > /dev/null; then
  echo "Found libtoolize"
  libtoolize -c
elif which glibtoolize > /dev/null; then
  echo "Found glibtoolize"
  glibtoolize -c
else
  echo "Failed to find libtoolize or glibtoolize, please ensure it is installed and accessible via your PATH env variable"
  exit 1
fi;

if [ "x$BS_GEN_DB_ES" = "xy" ] && [ "x$BS_GEN_SPO_MPOOL_RING" = "xy" ] ; then
  echo "[$0]: Compile With ElasticSearch and Mpool-Ring."
  sed -i "s/^libspo_a_SOURCES+=.*/libspo_a_SOURCES+=\$(libspo_a_SOURCES_es) \$(libspo_a_SOURCES_mr)/g" "./src/output-plugins/Makefile.am"
elif [ "x$BS_GEN_DB_ES" = "xy" ]; then
  echo "[$0]: Compile With ElasticSearch."
  sed -i "s/^libspo_a_SOURCES+=.*/libspo_a_SOURCES+=\$(libspo_a_SOURCES_es)/g" "./src/output-plugins/Makefile.am"
elif [ "x$BS_GEN_SPO_DB_MYSQL" = "xy" ]; then
  echo "[$0]: Compile With Mysql."
  sed -i "s/^libspo_a_SOURCES+=.*/libspo_a_SOURCES+=\$(libspo_a_SOURCES_my)/g" "./src/output-plugins/Makefile.am"
else
  echo "[$0]: No Support Database, exit with error."
  exit 2
fi

#autoreconf -fv --install
autoreconf -fvi
echo "You can now run \"./configure\" and then \"make\"."
