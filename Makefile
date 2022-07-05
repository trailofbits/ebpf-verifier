KERNEL_VERSIONS = 5.18.8 5.15.51 5.15 5.2

# make the bitcode for all of the kernel versions
bitcode: backup/ $(filter $(KERNEL_VERSIONS), $(wildcard *))


$(KERNEL_VERSIONS): %: ../linux-%/
	echo $<

clean:
	rm -f harness
