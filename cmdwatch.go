package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/fsnotify.v1"
)

var (
	stdout    = os.Stdout
	stderr    = os.Stderr
	dperms    = os.FileMode(0644)
	okl, errl *log.Logger
	dampen    time.Duration
)

func init() {
	var err error
	dampen, err = time.ParseDuration("50ms")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Bad wait time: %v\n", err)
	}
}

var watchedPaths = struct {
	Paths map[string]bool
	Lock  *sync.Mutex
}{map[string]bool{}, new(sync.Mutex)}

func lock() {
	watchedPaths.Lock.Lock()
}

func unlock() {
	watchedPaths.Lock.Unlock()
}

type command struct {
	Comm    string
	Program string
	Args    []string
}

func newCommand(cmdLine string) *command {
	if len(cmdLine) == 0 {
		return nil
	}

	ss := strings.Split(cmdLine, " ")
	for i := range ss {
		ss[i] = strings.TrimSpace(ss[i])
	}

	return &command{
		Comm:    cmdLine,
		Program: ss[0],
		Args:    ss[1:],
	}
}

func (cmd *command) ExecCmd() *exec.Cmd {
	ecmd := exec.Command(cmd.Program, cmd.Args...)
	ecmd.Stdout = os.Stdout
	ecmd.Stderr = os.Stderr
	return ecmd
}

func (cmd *command) Run() {
	ecmd := cmd.ExecCmd()
	start := time.Now()
	err := ecmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		errl.Printf("FAILED: %s - %v", cmd.Comm, err)
	} else {
		okl.Printf("SUCCESS: %s (%s)", cmd.Comm, elapsed)
	}
}

type watcher struct {
	cmd      *command
	pattern  *regexp.Regexp
	notUntil time.Time
}

func (w *watcher) Run(path string) {
	if w.pattern.MatchString(path) {
		if time.Now().Before(w.notUntil) {
			return
		}
		okl.Printf("%s triggered %s", path, w.cmd.Comm)
		w.notUntil = time.Now().Add(dampen)
		w.cmd.Run()
	}
}

func newWatcher(cmd *command, pattern string) (*watcher, error) {
	patre, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	w := new(watcher)
	w.cmd = cmd
	w.pattern = patre
	return w, nil
}

func setupLogging() {
	okl = log.New(os.Stdout, "cmdwatch:", log.LstdFlags)
	errl = log.New(os.Stderr, "cmdwatch:", log.LstdFlags)
}

var ignoreDirs = map[string]bool{
	".git":  true,
	".hg":   true,
	"darcs": true,
}

func ignoreDirP(path string) bool {
	return ignoreDirs[filepath.Base(path)]
}

func addWatch(w *fsnotify.Watcher, path string, fi os.FileInfo) error {
	if fi.Mode().IsDir() {
		if ignoreDirP(path) {
			return filepath.SkipDir
		}
	}

	if strings.HasPrefix(filepath.Base(path), ".") {
		return nil
	}

	if _, watching := watchedPaths.Paths[path]; watching {
		return nil
	}

	err := w.Add(path)
	if err == nil {
		lock()
		defer unlock()
		watchedPaths.Paths[path] = fi.Mode().IsDir()
	}
	return err
}

func newWalker(w *fsnotify.Watcher) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info == nil {
			return nil
		}

		return addWatch(w, path, info)
	}
}

func removePaths(w *fsnotify.Watcher, path string, top bool) error {
	if _, watching := watchedPaths.Paths[path]; !watching {
		return nil
	}

	err := w.Remove(path)
	if err != nil {
		return err
	}

	if top {
		lock()
		defer unlock()
	}

	d := watchedPaths.Paths[path]
	delete(watchedPaths.Paths, path)
	if d {
		for p := range watchedPaths.Paths {
			if !strings.HasPrefix(p, path) {
				continue
			}
			err = removePaths(w, p, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func isDirP(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return fi.Mode().IsDir(), nil
}

func scanFiles(path string, w *fsnotify.Watcher) error {
	walker := newWalker(w)

	isDir, err := isDirP(path)
	if err != nil {
		return err
	}

	if isDir {
		return filepath.Walk(path, walker)
	} else {
		return w.Add(path)
	}
}

var ops = map[fsnotify.Op]string{
	fsnotify.Create: "create",
	fsnotify.Write:  "write",
	fsnotify.Remove: "remove",
	fsnotify.Rename: "rename",
	fsnotify.Chmod:  "chmod",
}

func eventHandler(ev *fsnotify.Event, w *fsnotify.Watcher, watchers []*watcher) {
	for i := range watchers {
		watchers[i].Run(ev.Name)
	}

	if ev.Op == fsnotify.Remove || ev.Op == fsnotify.Rename {
		go func() {
			err := removePaths(w, ev.Name, true)
			if err != nil {
				errl.Printf("remove paths: %v", err)
			}
		}()
	}

	if ev.Op == fsnotify.Chmod || ev.Op == fsnotify.Remove {
		return
	}

	go func() {
		err := scanFiles(ev.Name, w)
		if err != nil {
			errl.Printf("scan files: %v", err)
		}
	}()
}

func scan(w *fsnotify.Watcher, watchers []*watcher) error {
	for {
		select {
		case ev := <-w.Events:
			eventHandler(&ev, w, watchers)
		case err := <-w.Errors:
			errl.Printf("scan: %v", err)
		}
	}
}

func watch(watchers []*watcher, paths []string) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	for _, path := range paths {
		err = scanFiles(path, w)
		if err != nil {
			return err
		}
	}

	return scan(w, watchers)
}

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Printf(`Usage: %s -c command -p pattern -t duration[files...]

        At least one command must be specified before any patterns; further
        patterns will use this command until the next command specifier.

        Patterns use RE2 syntax[1].

        If no files are specified, the current directory is chosen.

        Errors are reported to standard error, while normal program output
        is reported to standard output.

	Duration is the minimum time between events.

        Example:
            %s -c make -p '\.h$' -p '\.c$' -c 'make pdf' -p '\.texi'
            will run make any time a C header or source file changes,
            or build a PDF any time the Texinfo sources change.
            

        [1] https://github.com/google/re2/wiki/Syntax
`, prog, prog)
}

var (
	errExpectArg = errors.New("not enough arguments")
	errNoCommand = errors.New("no command specified")
)

func parseArgs() ([]*watcher, []string, error) {
	var (
		paths      []string
		watchers   []*watcher
		curCommand *command
	)

	args := os.Args[1:]
	for {
		if len(args) == 0 {
			break
		}

		switch args[0] {
		case "-c":
			if len(args) < 2 {
				return nil, nil, errExpectArg
			}
			curCommand = newCommand(args[1])
			args = args[2:]
		case "-p":
			if len(args) < 2 {
				return nil, nil, errExpectArg
			}

			if curCommand == nil {
				return nil, nil, errNoCommand
			}

			w, err := newWatcher(curCommand, args[1])
			if err != nil {
				return nil, nil, err
			}

			watchers = append(watchers, w)
			args = args[2:]
		case "-t":
			if len(args) < 2 {
				return nil, nil, errExpectArg
			}

			dur, err := time.ParseDuration(args[1])
			if err != nil {
				return nil, nil, err
			}

			dampen = dur
			args = args[2:]
		case "-h":
			usage()
			os.Exit(0)
		default:
			if strings.HasPrefix(args[0], "-") {
				usage()
				os.Exit(1)
			}
			paths = append(paths, args[0])
			args = args[1:]
		}
	}

	if len(paths) == 0 {
		paths = []string{"."}
	}

	if len(watchers) == 0 {
		if curCommand == nil {
			usage()
			os.Exit(1)
		}

		w, err := newWatcher(curCommand, ".")
		if err != nil {
			return nil, nil, err
		}

		watchers = []*watcher{w}
	}

	return watchers, paths, nil
}

func main() {
	setupLogging()

	watchers, paths, err := parseArgs()
	if err != nil {
		errl.Fatalf("can't start: %v", err)
	}

	err = watch(watchers, paths)
	if err != nil {
		errl.Fatalf("watch: %v", err)
	}

	os.Exit(0)
}
