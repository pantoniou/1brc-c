#!/bin/sh
perf record --call-graph dwarf ./1brc-c measurements.txt $@
