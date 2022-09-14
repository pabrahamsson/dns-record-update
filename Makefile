TAG?=cf-dyn-dns-update:latest
clean:
				cargo clean

debug:
				cargo build

release:
				cargo build -r

docker-debug-build: debug
				podman build -t $(TAG) . -f Dockerfile.local

docker-release-build: release
				podman build -t $(TAG) . -f Dockerfile.local-release

docker-push:
				podman push $(TAG)

docker-debug: docker-debug-build docker-push

docker-release: docker-release-build docker-push
