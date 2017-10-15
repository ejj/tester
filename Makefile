SHELL := /bin/bash
REPO = keldaio

docker-build:
	docker build -t ${REPO}/tester .

docker-push: docker-build
	docker push ${REPO}/tester

# Include all .mk files so you can have your own local configurations
include $(wildcard *.mk)
