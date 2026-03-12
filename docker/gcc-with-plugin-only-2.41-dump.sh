#!/usr/bin/env bash
exec gcc \
  -fplugin=/home/jiwoo/workspace/plugin/callsite_plugin.so \
  -fplugin-arg-callsite_plugin-outdir=/home/jiwoo/workspace/out/2.41-dump \
  "$@"
