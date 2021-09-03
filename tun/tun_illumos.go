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

type NativeTun struct {
	name    string
	tunFile *os.File
	events  chan Event
	errors  chan error
}

// XXX How do I test if this is actually working?
func (tun *NativeTun) routineRouteListener() {
	var (
		statusUp  bool
		statusMTU int
	)

	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(tun.tunFile.Name())
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
			tun.errors <- err
			return
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
	for _, proto := range []int{unix.AF_INET, unix.AF_INET6} {
		ip_fd, err := unix.Socket(proto, unix.SOCK_DGRAM, 0)
		if err != nil {
			return fmt.Errorf("could not open Socket of type %v", proto)
		}

		// illumos defines the ioctl number as a signed int, but the
		// common x/sys/unix functions use uint. Hand-cast things to help
		// the compiler figure it out.
		reqnum := int(unix.SIOCGLIFMUXID)
		if err := unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
			continue
		}

		id := l.GetLifruInt()

		if err := unix.IoctlSetInt(ip_fd, unix.I_PUNLINK, id); err != nil {
			continue
		}

		unix.Close(ip_fd)
	}
	return nil
}

func CreateTUN(name string, mtu int) (Device, error) {
	if name != "tun" {
		return nil, fmt.Errorf("Interface name must be 'tun'")
	}

	dev_node := "/dev/tun"
        tunFile, err := os.OpenFile(dev_node, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open TUN (%s)", dev_node)
	}
        fd := int(tunFile.Fd())

	// Ask the TUN driver for a new PPA number:
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
			tunFile.Close()
			return nil, err
		}
		break
	}

	name = fmt.Sprintf("tun%d", ppa)
	// Immediately do a full cleanup of anything stale left behind by a previous crash
	tunDestroy(name)

	ip_fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open a UDP Socket")
	}
	defer unix.Close(ip_fd)

	// Unclear why, but we need to open a second handle on the tun device for
	// the ioctls that follow. Reusing the existing one does not work.
	if_fd, err := unix.Open(dev_node, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open TUN (%s)", dev_node)
	}
	defer unix.Close(if_fd)

	// Push the IP module onto the new TUN device.
	if err = unix.IoctlSetString(if_fd, unix.I_PUSH, "ip"); err != nil {
		tunFile.Close()
		tunDestroy(name)
		return nil, fmt.Errorf("unable to push IP module: %v", err)
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	req := int(unix.IF_UNITSEL)
	err = unix.IoctlSetPointerInt(if_fd, uint(req), ppa)
	if err != nil {
		tunFile.Close()
		tunDestroy(name)
		return nil, fmt.Errorf("unable to IF_UNITSEL: %v", err)
	}

	muxid, err := unix.IoctlSetIntRetInt(ip_fd, unix.I_PLINK, if_fd)
	if err != nil {
		tunFile.Close()
		tunDestroy(name)
		return nil, fmt.Errorf("unable to I_PLINK: %v", err)
	}

	var l unix.Lifreq
	if err := l.SetName(name); err != nil {
		tunFile.Close()
		tunDestroy(name)
		return nil, fmt.Errorf("failed to set name on Lifreq :%v", err)
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	reqnum := int(unix.SIOCSLIFMUXID)
	l.SetLifruInt(muxid)
	if err = unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
		tunFile.Close()
		tunDestroy(name)
		return nil, fmt.Errorf("unable to SIOCSLIFMUXID: %v", err)
	}

	file := os.NewFile(uintptr(fd), name)
	return CreateTUNFromFile(file, mtu)
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
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
	return tun.tunFile.Name(), nil
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
		_, read, _, err := unix.Getmsg(int(tun.tunFile.Fd()), nil, buf[offset:])
		if err != nil {
			return 0, err
		}
		return len(read), nil
	}
}

func (tun *NativeTun) Write(buf []byte, offset int) (int, error) {
	if err := unix.Putmsg(int(tun.tunFile.Fd()), nil, buf[offset:], 0); err != nil {
		return 0, err
	}
	return len(buf), nil
}

func (tun *NativeTun) Flush() error {
	return nil
}

func (tun *NativeTun) Close() error {
	tunDestroy(tun.tunFile.Name())

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
	if err := l.SetName(tun.tunFile.Name()); err != nil {
		return err
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	reqnum := int(unix.SIOCSLIFMTU)
	l.SetLifruUint(uint(n))
	if err = unix.IoctlLifreq(fd, uint(reqnum), &l); err != nil {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.tunFile.Name(), err)
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
	if err := l.SetName(tun.tunFile.Name()); err != nil {
		return 0, err
	}

	// illumos defines the ioctl number as a signed int, but the
	// common x/sys/unix functions use uint. Hand-cast things to help
	// the compiler figure it out.
	reqnum := int(unix.SIOCGLIFMTU)
	if err = unix.IoctlLifreq(fd, uint(reqnum), &l); err != nil {
		return 0, fmt.Errorf("unable to SIOCGLIFMTU: %v", err)
	}
	return int(l.GetLifruUint()), nil
}
