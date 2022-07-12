.PHONY: test docker push

IMAGE            ?= hjacobs/kube-downscaler
VERSION          ?= $(shell git describe --tags --always --dirty)
TAG              ?= $(VERSION)

default: docker

.PHONY: install
install:
	poetry install

.PHONY: lint
lint: install
	poetry run pre-commit run --all-files


test: lint install
	poetry run coverage run --source=kube_downscaler -m py.test -v
	poetry run coverage report

version:
	sed -i "s/version: v.*/version: v$(VERSION)/" deploy/*.yaml
	sed -i "s/kube-downscaler:.*/kube-downscaler:$(VERSION)/" deploy/*.yaml

docker:
	docker buildx create --use
	docker buildx build --rm --build-arg "VERSION=$(VERSION)" -t "$(IMAGE):$(TAG)" -t "$(IMAGE):latest" --platform linux/amd64,linux/arm64 .
	@echo 'Docker image $(IMAGE):$(TAG) multi-arch was build (cannot be used).'

push:
	docker buildx create --use
	docker buildx build --rm --build-arg "VERSION=$(VERSION)" -t "$(IMAGE):$(TAG)" -t "$(IMAGE):latest" --platform linux/amd64,linux/arm64 --push .
	@echo 'Docker image $(IMAGE):$(TAG) multi-arch can now be used.'
