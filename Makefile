README.pod: jperms.pl
	podselect jperms.pl > README.pod

docker-build:
	docker build -t jperms-test .

test:
	docker run -v ${PWD}:/jperms -w /tmp --name jperms-test jperms-test \
		/jperms/runtests
	docker rm jperms-test
