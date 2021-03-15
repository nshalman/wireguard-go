/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Joyent, Inc.
 */

// +build illumos,amd64

package tun

import (
	"fmt"

	"golang.org/x/sys/unix"
	"os"
)

// NativeTun is the OS-specific implementation of a tun interface.
type NativeTun struct {
	tunFile *os.File /* TUN device file */
	ip_fd   int      /* IP device fd */
	name    string   /* Interface name */
	mtu     int

	events chan Event
	errors chan error
}

// Name implements the Device interface
func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

// Flush implements the Device interface
func (tun *NativeTun) Flush() error {
	// TODO: can flushing be implemented by buffering and using sendmmsg?
	return nil
}

// Read implements the Device interface
func (tun *NativeTun) Read(buf []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		_, read, _, err := unix.Getmsg(int(tun.tunFile.Fd()), nil, buf[offset:])
		if err != nil {
			return 0, err
		}
		return len(read), nil
	}
}

// Write implements the Device interface
func (tun *NativeTun) Write(buf []byte, offset int) (int, error) {
	if err := unix.Putmsg(int(tun.tunFile.Fd()), nil, buf[offset:], 0); err != nil {
		return 0, err
	}
	return len(buf), nil
}

// File implements the Device interface
func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

// MTU implements the Device interface
func (tun *NativeTun) MTU() (int, error) {
	return tun.mtu, nil
}

// Events implements the Device interface
func (tun *NativeTun) Events() chan Event {
	return tun.events
}

// Close implements the Device interface
func (tun *NativeTun) Close() error {
	if tun.ip_fd >= 0 {
		id, err := unix.IoctlGetIPMuxID(tun.ip_fd, tun.name)
		if err != nil {
			return err
		}

		if err = unix.IoctlPunlink(tun.ip_fd, id); err != nil {
			return err
		}

		unix.Close(tun.ip_fd)
		tun.ip_fd = -1
	}

	if tun.tunFile != nil {
		tun.tunFile.Close()
		tun.tunFile = nil
	}

	if tun.events != nil {
		close(tun.events)
	}

	return nil
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	/*
	 * XXX It's not currently clear to me how to take a TUN file descriptor
	 * and determine the attached PPA.
	 *
	 * XXX Based on the current architecture of the daemon, we need to be
	 * able to reconstitute our NativeTun object from just a file
	 * descriptor number as the fd number is passed (with no other
	 * information) through the environment to the child.  For now, use the
	 * "-f" flag.
	 */
	return nil, fmt.Errorf("CreateTUNFromFile() not currently supported")
}

func CreateTUN(name string, mtu int) (Device, error) {
	if name != "tun" {
		return nil, fmt.Errorf("Interface name must be 'tun'")
	}

	/*
	 * To establish a "tun" interface, we need to open a few file
	 * descriptors.
	 */
	ip_node := "/dev/udp"
	dev_node := "/dev/tun"

	/*
	 * First, the IP driver:
	 */
	ip_fd, err := unix.Open(ip_node, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open IP (%s)", ip_node)
	}

	/*
	 * Now, the TUN driver.  Note that we use "os.OpenFile()" instead of
	 * "unix.OpenFile()" so that we get the os.File object here.  The rest
	 * of the Wireguard API seems to depend on that functionality.
	 */
	tunFile, err := os.OpenFile(dev_node, unix.O_RDWR, 0)
	if err != nil {
		unix.Close(ip_fd)
		return nil, fmt.Errorf("Could not open TUN (%s)", dev_node)
	}
	fd := int(tunFile.Fd())

	/*
	 * Ask the TUN driver for a new PPA number:
	 */
	var ppa int
	for try := 0; try < 128; try++ {
		ppa, err = unix.IoctlTunNewPPA(fd, try)
		if err != nil {
			if err == unix.EEXIST {
				// PPA already in use, try the next one.
				continue
			}
			unix.Close(ip_fd)
			tunFile.Close()
			return nil, err
		}
		break
	}

	name = fmt.Sprintf("tun%d", ppa)

	/*
	 * Open another temporary file descriptor to the TUN driver.
	 * XXX It's not clear if this is actually needed, or if we could
	 * reuse the fd we got above...
	 */
	if_fd, err := unix.Open(dev_node, unix.O_RDWR, 0)
	if err != nil {
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, fmt.Errorf("Could not open second TUN (%s)",
			dev_node)
	}

	/*
	 * Push the IP module onto the new TUN device.
	 */
	if err = unix.IoctlSetString(if_fd, unix.I_PUSH, "ip"); err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	// Illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	req := int(unix.IF_UNITSEL)
	if err = unix.IoctlSetPointerInt(if_fd, uint(req), ppa); err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	muxid, err := unix.IoctlPlink(ip_fd, if_fd)
	if err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	/*
	 * XXX It would seem that we can now close this file descriptor,
	 * because of the persistent link established above.
	 */
	unix.Close(if_fd)

	if err = unix.IoctlSetIPMuxID(ip_fd, name, muxid); err != nil {
		unix.IoctlPunlink(ip_fd, muxid)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	tun := &NativeTun{
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
		mtu:     mtu, /* XXX We should do something with the MTU! */
		name:    name,
		tunFile: tunFile,
		ip_fd:   ip_fd,
	}

	defer func() {
		/*
		 * XXX For now, we'll just send a link up event straight away.
		 */
		tun.events <- EventUp
	}()

	return tun, nil
}
