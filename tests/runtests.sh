echo "Running unit tests:"
for i in {tests/*_tests,tests/**/*_tests}
do
	echo $i
    if test -f $i
    then
        if $VALGRIND ./$i 2>> tests/tests.log
        then
            echo $i PASS
            echo 
        else
            echo "ERROR in test $i: here's tests/tests.log"
            echo "------"
            tail tests/tests.log
            exit 1
        fi
    fi
done

echo "" 
