#!/bin/bash

failed=0
for t in samples/*.txt; do
	echo -n "checking $t ${t%.txt}.out ... "
	./1brc-c $@ "$t" | diff -u - "${t%.txt}.out" >/dev/null 2>&1
	if test $? -ne 0; then
		tput setaf 1
		echo "FAIL"
		tput sgr0
		./1brc-c $@ "$t" | diff -u - "${t%.txt}.out"
		failed=1
	else
		tput setaf 2
		echo "OK"
		tput sgr0
	fi
done

test $failed -eq 0 || exit 1
