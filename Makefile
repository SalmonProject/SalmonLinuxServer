salmon:
	gcc -pthread -o salmond salmon_source/globals.c salmon_source/utility.c salmon_source/connection_logic.c salmon_source/connect_tls.c salmon_source/control_softether.c salmon_source/tls_swrap.c salmon_source/stringLL.c -lpolarssl


.PHONY: clean

clean:
	rm -f salmond
