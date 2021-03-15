module github.com/tailscale/wireguard-go

go 1.15

require (
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/sys v0.0.0-20210105210732-16f7687f5001
)

replace golang.org/x/sys => /home/admin/sys
