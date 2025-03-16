check_execv:
	sudo python3 check_execv.py 

show_trace_pipe:
	sudo python3 show_trace_pipe.py

docker-build:
	docker build -t bcc-container-demo .

docker-run:
	docker run --privileged --cap-add=SYS_ADMIN -it --name bcc-demo bcc-container-demo

docker-rm:
	docker rm bcc-demo

