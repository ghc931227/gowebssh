package internal

import (
	"io/ioutil"
	"log"
	"time"
)

var (
	DefaultTerm        = TermXterm256Color
	DefaultConnTimeout = 15 * time.Second
	DefaultLogger      = log.New(ioutil.Discard, "[webssh] ", log.Ltime|log.Ldate)
	DefaultBuffSize    = uint32(8192)
	DefaultCols        = 80
	DefaultRows        = 24
)
