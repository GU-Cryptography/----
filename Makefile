all:
	gcc *.c -I. -L. -lhsm_sdk
clean:
	rm -f *.out