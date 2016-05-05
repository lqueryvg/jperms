# 1. update README.pod whenever the Perl changes
# 2. assist with local docker testing

README.pod: jperms.pl
	podselect jperms.pl > README.pod

docker:
	docker build -t jperms-test .

test: clean
	docker run -v ${PWD}:/jperms -w /jperms --name jperms-test jperms-test \
		/jperms/runtests

clean:
	-docker rm jperms-test
