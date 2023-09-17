TAG?=cf-dyn-dns-update:latest
clean:
				cargo clean

debug:
				cargo build

release:
				cargo build -r

container-debug-build: debug
				podman pull registry.access.redhat.com/ubi9/ubi-minimal:latest
				podman build -t $(TAG) . -f Containerfile.local

container-release-build: release
				podman pull registry.access.redhat.com/ubi9/ubi-minimal:latest
				podman build -t $(TAG) . -f Containerfile.local-release

container-push:
				podman push $(TAG)

container-debug: container-debug-build container-push

container-release: container-release-build container-push
