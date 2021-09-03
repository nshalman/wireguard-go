//go:build illumos && amd64
// +build illumos,amd64

/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Joyent, Inc.
 */

package tun

import (
	"fmt"

	"golang.org/x/sys/unix"
	"os"
)

const (
	IP_NODE  = "/dev/udp"
	IP6_NODE = "/dev/udp6"
)

// NativeTun is the OS-specific implementation of a tun interface.
type NativeTun struct {
	tunFile *os.File /* TUN device file */
	name    string   /* Interface name */

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
	ip_fd, err := unix.Open(IP_NODE, unix.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("Could not open IP (%s)", IP_NODE)
	}
	defer unix.Close(ip_fd)

	var l unix.Lifreq
	if err := l.SetName(tun.name); err != nil {
		return 0, err
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	reqnum := int(unix.SIOCGLIFMTU)
	if err = unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
		return 0, fmt.Errorf("unable to SIOCGLIFMTU: %v", err)
	}
	return int(l.GetLifruUint()), nil
}

// Events implements the Device interface
func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func closeTun(name string) error {
	for _, node := range []string{IP_NODE, IP6_NODE} {
		ip_fd, err := unix.Open(node, unix.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("Could not open IP (%s)", node)
		}

		var l unix.Lifreq
		if err := l.SetName(name); err != nil {
			return err
		}

		// illumos defines the ioctl number as a signed int, but the
		// common x/sys/unix functions use uint. Hand-cast things to help
		// the compiler figure it out.
		reqnum := int(unix.SIOCGLIFMUXID)
		if err := unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
			return err
		}

		id := l.GetLifruInt()

		if err := unix.IoctlSetInt(ip_fd, unix.I_PUNLINK, id); err != nil {
			return err
		}

		unix.Close(ip_fd)
	}
	return nil
}

// Close implements the Device interface
func (tun *NativeTun) Close() error {
	closeTun(tun.name)

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
	tun := &NativeTun{
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
		name:    file.Name(),
		tunFile: file,
	}
	return tun, nil
}

func CreateTUN(name string, mtu int) (Device, error) {
	if name != "tun" {
		return nil, fmt.Errorf("Interface name must be 'tun'")
	}

	/*
	 * To establish a "tun" interface, we need to open a few file
	 * descriptors.
	 */
	dev_node := "/dev/tun"

	/*
	 * First, the IP driver:
	 */
	ip_fd, err := unix.Open(IP_NODE, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open IP (%s)", IP_NODE)
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
	var s unix.Strioctl
	s.Cmd = unix.TUNNEWPPA
	for try := 0; try < 128; try++ {
		s.SetInt(try)
		ppa, err = unix.IoctlSetStrioctlRetInt(fd, unix.I_STR, &s)
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
	// Immediately do a full cleanup of anything stale left behind by a previous crash
	closeTun(name)

	/*
	 * Open another temporary file descriptor to the TUN driver.
	 * XXX It's not clear if this is actually needed, or if we could
	 * reuse the fd we got above...
	 */
	if_fd, err := unix.Open(dev_node, unix.O_RDWR, 0)
	if err != nil {
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("could not open second TUN (%s)",
			dev_node)
	}

	/*
	 * Push the IP module onto the new TUN device.
	 */
	if err = unix.IoctlSetString(if_fd, unix.I_PUSH, "ip"); err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("unable to push IP module: %v", err)
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	req := int(unix.IF_UNITSEL)
	err = unix.IoctlSetPointerInt(if_fd, uint(req), ppa)
	if err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("unable to IF_UNITSEL: %v", err)
	}

	muxid, err := unix.IoctlSetIntRetInt(ip_fd, unix.I_PLINK, if_fd)
	if err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("unable to I_PLINK: %v", err)
	}

	/*
	 * XXX It would seem that we can now close this file descriptor,
	 * because of the persistent link established above.
	 */
	unix.Close(if_fd)

	var l unix.Lifreq
	if err := l.SetName(name); err != nil {
		unix.IoctlSetInt(ip_fd, unix.I_PUNLINK, muxid)
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("failed to set name on Lifreq :%v", err)
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	reqnum := int(unix.SIOCSLIFMUXID)
	l.SetLifruInt(muxid)
	if err = unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
		unix.IoctlSetInt(ip_fd, unix.I_PUNLINK, muxid)
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("unable to SIOCSLIFMUXID: %v", err)
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	reqnum = int(unix.SIOCSLIFMTU)
	l.SetLifruUint(uint(mtu))
	if err = unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
		unix.IoctlSetInt(ip_fd, unix.I_PUNLINK, muxid)
		unix.Close(ip_fd)
		tunFile.Close()
		closeTun(name)
		return nil, fmt.Errorf("unable to SIOCSLIFMTU: %v", err)
	}

	tun := &NativeTun{
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
		name:    name,
		tunFile: tunFile,
	}

	defer func() {
		/*
		 * XXX For now, we'll just send a link up event straight away.
		 */
		tun.events <- EventUp
	}()

	return tun, nil
}
