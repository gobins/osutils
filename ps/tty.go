package main

// import (
// 	"os"
// 	"path/filepath"
// 	"strings"
// 	"syscall"
// )

// var (
// 	MINORBITS = uint(20)
// 	MINORMASK = uint((uint(1) << MINORBITS) - 1)
// )

// func Major(dev uint) int {
// 	return int(dev >> MINORBITS)
// }

// func Minor(dev uint) int {
// 	return int(dev & MINORMASK)
// }

// func Mkdev(majorNumber int, minorNumber int) uint {
// 	return uint((majorNumber << MINORBITS) | minorNumber)
// }

// func mapTTY() map[uint]string {
// 	ttymap := make(map[uint]string)
// 	err := filepath.Walk("/dev", func(path string, file os.FileInfo, err error) error {
// 		if err == nil && strings.Contains(file.Name(), "tty") {
// 			sys, ok := file.Sys().(*syscall.Stat_t)
// 			if ok {
// 				ttymap[uint(sys.Rdev)] = file.Name()
// 			}
// 		}
// 		return ttymap
// 	})
// 	if err != nil {
// 		filepath.SkipDir.Error()
// 	}
// 	return ttymap
// }
