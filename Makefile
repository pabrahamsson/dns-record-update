TAG?=cf-dyn-dns-update:latest
clean:
				cargo clean

debug:
				cargo build

release:
				cargo build -r

docker-debug-build: debug
				podman pull registry.access.redhat.com/ubi9/ubi-minimal:latest
				podman build -t $(TAG) . -f Dockerfile.local

docker-release-build: release
				podman pull registry.access.redhat.com/ubi9/ubi-minimal:latest
				podman build -t $(TAG) . -f Dockerfile.local-release

docker-push:
				podman push $(TAG)

docker-debug: docker-debug-build docker-push

docker-release: docker-release-build docker-push
