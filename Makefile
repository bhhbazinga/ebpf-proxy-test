all: sockmap_kern.c proxy_server.c echo_server.c net.c common.h
	clang -g -Wall -Wextra -O2 \
		net.c \
		echo_server.c \
		-o echo_server

	clang -g -Wall -Wextra -O2 \
		net.c \
		proxy_server.c \
		-o ebpf_proxy_server -lpthread -lbpf -DUSE_SOCKMAP

	clang -g -Wall -Wextra -O2 \
		net.c \
		proxy_server.c \
		-o normap_proxy_server -lpthread -lbpf

	clang -g -Wall -Wextra -O2 \
		net.c \
		benchmark.c \
		-o benchmark

	clang -O2 -emit-llvm -c sockmap_kern.c -o - | \
		llc -march=bpf -mcpu=probe -filetype=obj -o sockmap_kern.o

clean:
	rm -f echo_server *proxy_server benchmark *.o 

.PHONY: all clean
