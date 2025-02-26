FROM python:3.12.9-alpine3.20 AS builder

WORKDIR /

# Install necessary build tools and dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev python3-dev py3-setuptools

RUN pip3 install poetry

COPY poetry.lock /
COPY pyproject.toml /

RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-dev --no-ansi

FROM python:3.12.9-alpine3.20

WORKDIR /

# copy pre-built packages to this image
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# now copy the actual code we will execute (poetry install above was just for dependencies)
COPY kube_downscaler /kube_downscaler

ARG VERSION=dev

RUN sed -i "s/__version__ = .*/__version__ = '${VERSION}'/" /kube_downscaler/__init__.py

ENTRYPOINT ["python3", "-m", "kube_downscaler"]
