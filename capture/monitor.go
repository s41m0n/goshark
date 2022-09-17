package capture

import (
	"fmt"
	"log"
	"plugin"

	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
)

type Module interface {
	Parse([]byte, gopacket.CaptureInfo)
	ParseConcurrent([]byte, gopacket.CaptureInfo, int)
}

func loadPlugin(mod string) (err error) {
	// load module: open the so file to load the symbols
	plug, err := plugin.Open(mod)
	if err != nil {
		return
	}

	// look up a symbol (an exported function or variable)
	symMonitor, err := plug.Lookup("Module")
	if err != nil {
		return
	}

	// Assert that loaded symbol is of a desired type
	monitor, ok := symMonitor.(Module)
	if !ok {
		return fmt.Errorf("[Loader] Problem Loading the Symbol")
	}
	log.Println("[Loader] Loaded Module", mod)
	module = monitor
	return
}

func watchEvent(watcher *fsnotify.Watcher, module string) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if (event.Op != fsnotify.Create && event.Op != fsnotify.Chmod) || event.Name != module {
				break
			}
			err := loadPlugin(event.Name)
			if err != nil {
				log.Println("Having problem loading new module, still using old one")
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}
}
