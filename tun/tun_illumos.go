//go:build illumos && amd64
// +build illumos,amd64

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 * Copyright 2019 Joyent, Inc.
 */

package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunNode = "/dev/tun"
)

type NativeTun struct {
	fd      int
	name    string
	tunFile *os.File
	events  chan Event
	errors  chan error
}

// XXX This is largely copied from the freebsd code...
// XXX How do I test if it is actually working?
func (tun *NativeTun) routineRouteListener() {
	var (
		statusUp  bool
		statusMTU int
	)

	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(tun.name)
		if err != nil {
			return -1, err
		}
		return iface.Index, nil
	}()
	if err != nil {
		tun.errors <- err
		return
	}

	defer close(tun.events)

	routeSocket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.errors <- err
		return
	}
	defer unix.Close(routeSocket)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(routeSocket, data)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				goto retry
			}
			tun.errors <- err
			return
		}

		if n < 14 {
			continue
		}

		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}

		iface, err := net.InterfaceByIndex(ifindex)
		if err != nil {
			//tun.errors <- err
			//return
			// XXX returning this error breaks everything??
			continue
		}

		// Up / Down event
		up := (iface.Flags & net.FlagUp) != 0
		if up != statusUp && up {
			tun.events <- EventUp
		}
		if up != statusUp && !up {
			tun.events <- EventDown
		}
		statusUp = up

		// MTU changes
		if iface.MTU != statusMTU {
			tun.events <- EventMTUUpdate
		}
		statusMTU = iface.MTU
	}
}

func tunDestroy(name string) error {
	var l unix.Lifreq
	if err := l.SetName(name); err != nil {
		return err
	}
	// cleanup both ipv4 and ipv6
	for _, proto := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(proto, unix.SOCK_DGRAM, 0)
		if err != nil {
			return fmt.Errorf("could not open Socket of type %v", proto)
		}

		// get the STREAMS muxid for the tun device stream
		reqnum := int(unix.SIOCGLIFMUXID)

		// illumos defines the ioctl number as a signed int, but the
		// common x/sys/unix functions use uint.
		if err := unix.IoctlLifreq(fd, uint(reqnum), &l); err != nil {
			continue
		}

		id := l.GetLifruInt()

		// Unlink the tun stream from the IP mutiplexor
		if err := unix.IoctlSetInt(fd, unix.I_PUNLINK, id); err != nil {
			continue
		}

		unix.Close(fd)
	}
	return nil
}

func CreateTUN(name string, mtu int) (Device, error) {
	ppa := -1
	if name != "tun" {
		_, err := fmt.Sscanf(name, "tun%d", &ppa)
		if err != nil || ppa < 0 {
			return nil, fmt.Errorf("Interface name must be tun[0-9]*")
		}
	}

	fd, err := unix.Open(tunNode, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open TUN (%s)", tunNode)
	}

	// The "tun" device is a STREAMS module.  We need to make a STREAMS ioctl
	// request to that module using the TUNNEWPPA command.  Returns the newly
	// allocated PPA number. Passing -1 will request a dynamically assinged
	// PPA. Passing a specific id will try to use the one specified.
	var s unix.Strioctl
	s.Cmd = unix.TUNNEWPPA
	s.SetInt(ppa)
	ppa, err = unix.IoctlSetStrioctlRetInt(fd, unix.I_STR, &s)
	if err != nil {
		return nil, err
	}

	assignedName := fmt.Sprintf("tun%d", ppa)

	// Immediately do a full cleanup of anything stale left behind by a previous crash
	tunDestroy(assignedName)

	dgramFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open a UDP Socket")
	}
	defer unix.Close(dgramFD)

	// Unclear why, but we need to open a second handle on the tun device for
	// the ioctls that follow. Reusing the existing one does not work.
	tunFD, err := unix.Open(tunNode, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open TUN (%s)", tunNode)
	}
	defer unix.Close(tunFD)

	// Push the IP module onto the new TUN device.
	if err = unix.IoctlSetString(tunFD, unix.I_PUSH, "ip"); err != nil {
		unix.Close(fd)
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to push IP module: %v", err)
	}

	// select which ppa we're trying to use
	req := int(unix.IF_UNITSEL)
	err = unix.IoctlSetPointerInt(tunFD, uint(req), ppa)
	if err != nil {
		unix.Close(fd)
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to IF_UNITSEL: %v", err)
	}

	// link the tun stream to the IP multiplexor
	muxid, err := unix.IoctlSetIntRetInt(dgramFD, unix.I_PLINK, tunFD)
	if err != nil {
		unix.Close(fd)
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to I_PLINK: %v", err)
	}

	var l unix.Lifreq
	if err := l.SetName(assignedName); err != nil {
		unix.Close(fd)
		tunDestroy(assignedName)
		return nil, fmt.Errorf("failed to set assignedName on Lifreq :%v", err)
	}

	// set the IP muxid
	reqnum := int(unix.SIOCSLIFMUXID)
	l.SetLifruInt(muxid)
	if err = unix.IoctlLifreq(dgramFD, uint(reqnum), &l); err != nil {
		unix.Close(fd)
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to SIOCSLIFMUXID: %v", err)
	}

	file := os.NewFile(uintptr(fd), assignedName)
	return CreateTUNFromFile(file, mtu)
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	// Rather than do complicated gymnastics trying to determine which tunN
	// we were using from the file descriptor, modify main.go to pass that
	// along in an environment variable and set it as the Name() property
	// of the os.File so that we can read it back here. Easy peasy.
	name := file.Name()
	if name == "" {
		return nil, fmt.Errorf("could not determine device name from os.File")
	}
	tun := &NativeTun{
		fd:      int(file.Fd()),
		name:    name,
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
	}

	go tun.routineRouteListener()

	err := tun.setMTU(mtu)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Read(buf []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		_, read, _, err := unix.Getmsg(tun.fd, nil, buf[offset:])
		if err != nil {
			return 0, err
		}
		return len(read), nil
	}
}

func (tun *NativeTun) Write(buf []byte, offset int) (int, error) {
	if err := unix.Putmsg(tun.fd, nil, buf[offset:], 0); err != nil {
		return 0, err
	}
	return len(buf), nil
}

func (tun *NativeTun) Flush() error {
	return nil
}

func (tun *NativeTun) Close() error {
	tunDestroy(tun.name)

	if tun.tunFile != nil {
		tun.tunFile.Close()
		tun.tunFile = nil
	}

	if tun.events != nil {
		close(tun.events)
	}

	return nil
}

func (tun *NativeTun) setMTU(n int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var l unix.Lifreq
	if err := l.SetName(tun.name); err != nil {
		return err
	}

	reqnum := int(unix.SIOCSLIFMTU)
	l.SetLifruUint(uint(n))
	if err = unix.IoctlLifreq(fd, uint(reqnum), &l); err != nil {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.name, err)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var l unix.Lifreq
	if err := l.SetName(tun.name); err != nil {
		return 0, err
	}

	reqnum := int(unix.SIOCGLIFMTU)
	if err = unix.IoctlLifreq(fd, uint(reqnum), &l); err != nil {
		return 0, fmt.Errorf("unable to SIOCGLIFMTU: %v", err)
	}
	return int(l.GetLifruUint()), nil
}
