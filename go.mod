module fouwels.com/bpf

go 1.24.10

require (
	github.com/aquasecurity/libbpfgo v0.1.1 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

replace github.com/aquasecurity/libbpfgo => ./libbpfgo // replace with modern version as submodule
