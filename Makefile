KERNEL_VERSIONS = 5.18.8 5.15.51 5.15

build-all:
	for dir in $(KERNEL_VERSIONS) ; do \
		cd $$dir && make all ; \
		cd .. ; \
	done

clean:
	for dir in $(KERNEL_VERSIONS) ; do \
		cd $$dir && make clean ; \
		cd .. ; \
	done
