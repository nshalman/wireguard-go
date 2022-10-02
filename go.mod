module golang.zx2c4.com/wireguard

go 1.18

require (
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	golang.org/x/sys v0.0.0-20220315194320-039c03cc5b86
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224
)

replace golang.org/x/sys => github.com/nshalman/sys v0.0.0-20221002153834-e7f8d0ebe900
