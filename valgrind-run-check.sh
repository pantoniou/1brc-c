#!/bin/bash
for t in samples/*.txt; do
	echo -n "checking $t ${t%.txt}.out ... "
	valgrind ./1brc-c $@ "$t" | diff -u - "${t%.txt}.out" >/dev/null 2>&1
	if test $? -ne 0; then
		tput setaf 1
		echo "FAIL"
		tput sgr0
		./1brc-c $@ "$t" | diff -u - "${t%.txt}.out"
	else
		tput setaf 2
		echo "OK"
		tput sgr0
	fi
done
