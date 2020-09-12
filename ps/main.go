package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/olekukonko/tablewriter"
)

type processinfo struct {
	Ttymap     map[uint]string
	Processmap map[string]process
}

type process struct {
	Name    string
	Cmd     string
	Pid     string
	Ppid    string
	Uid     UID
	Gid     GID
	Umask   string
	State   string
	Threads []thread
	Tty     string
}

type thread struct {
	threadID string
}

type UID struct {
	Real       string
	Effective  string
	SavedSet   string
	FileSystem string
}

type GID struct {
	Real       string
	Effective  string
	SavedSet   string
	FileSystem string
}

const (
	//PROC /proc directory
	PROC = "/proc"
	//STAT /proc/[pid]/stat filename
	STAT = "stat"
	//STAT /proc/[pid]/status filename
	STATUS = "status"
)

func main() {
	var pinfo processinfo
	pinfo.Processmap = make(map[string]process)
	pinfo.Ttymap = mapTTY()

	files, err := ioutil.ReadDir(PROC)
	if err != nil {
		fmt.Println(err)
	}
	var validPID = regexp.MustCompile(`^[0-9]+$`)
	for _, f := range files {
		if f.IsDir() && validPID.MatchString(f.Name()) {
			p := process{
				Pid: f.Name(),
			}
			pinfo.parseStat(p.Pid)
			pinfo.parseStatus(p.Pid)
		}
	}
	table := tablewriter.NewWriter(os.Stdout)
	for _, proc := range pinfo.Processmap {
		table.Append([]string{proc.Pid, proc.Ppid, proc.Tty, "", proc.Name})
	}
	table.SetHeader([]string{"PID", "PPID", "TTY", "TIME", "CMD"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.Render()
}

func (pinfo *processinfo) parseStat(pid string) error {
	var p = process{
		Pid: pid,
	}
	if _, ok := pinfo.Processmap[pid]; ok {
		p = pinfo.Processmap[pid]
	}

	file, err := os.Open(filepath.Join(PROC, pid, STAT))
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	values := strings.Split(line, " ")
	p.Name = values[1][1 : len(values[1])-1]
	p.Ppid = values[3]
	p.State = values[2]
	devNumber, _ := strconv.Atoi(values[6])

	p.Tty = pinfo.Ttymap[uint(devNumber)]
	if p.Tty == "" {
		p.Tty = "?"
	}

	pinfo.Processmap[pid] = p

	return nil
}

func (p *processinfo) parseStatus(pid string) error {
	var proc process
	if _, ok := p.Processmap[pid]; ok {
		proc = p.Processmap[pid]
	}
	file, err := os.Open(filepath.Join(PROC, pid, STATUS))
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		switch fields[0] {
		case "Umask":
			proc.Umask = strings.TrimSpace(fields[1])
		case "Uid":
			vals := strings.Fields(fields[1])
			if len(vals) < 4 {
				continue
			} else {
				proc.Uid = UID{
					Real:       vals[0],
					Effective:  vals[1],
					SavedSet:   vals[2],
					FileSystem: vals[3],
				}
			}
		case "Gid":
			vals := strings.Fields(fields[1])
			if len(vals) < 4 {
				continue
			} else {
				proc.Gid = GID{
					Real:       vals[0],
					Effective:  vals[1],
					SavedSet:   vals[2],
					FileSystem: vals[3],
				}
			}

		}
	}
	p.Processmap[pid] = proc
	return nil
}

var (
	MINORBITS = uint(20)
	MINORMASK = uint((uint(1) << MINORBITS) - 1)
)

func Major(dev uint) int {
	return int(dev >> MINORBITS)
}

func Minor(dev uint) int {
	return int(dev & MINORMASK)
}

func Mkdev(majorNumber int, minorNumber int) uint {
	return uint((majorNumber << MINORBITS) | minorNumber)
}

func mapTTY() map[uint]string {
	ttymap := make(map[uint]string)
	err := filepath.Walk("/dev", func(path string, file os.FileInfo, err error) error {
		if err != nil {
			filepath.SkipDir.Error()
		}
		if err == nil && strings.Contains(file.Name(), "tty") {
			sys, ok := file.Sys().(*syscall.Stat_t)
			if ok {
				ttymap[uint(sys.Rdev)] = file.Name()
			}
		}
		return nil
	})

	err = filepath.Walk("/dev/pts", func(path string, file os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
		} else {
			if !file.IsDir() {

				sys, ok := file.Sys().(*syscall.Stat_t)
				if ok {
					ttymap[uint(sys.Rdev)] = "pts/" + file.Name()
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	return ttymap
}
