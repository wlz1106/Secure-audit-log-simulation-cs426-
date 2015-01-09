all:log_shell

log_shell:log_shell.cpp
	g++ -o log_shell -lcrypto log_shell.cpp
clean:
	rm -rf log_shell
