package main

import (
	"io"
	"log"
	"os"

	"github.com/karlpokus/jwt"
)

var version string

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	// let's dump version first
	log.Println("WIP!")
	log.Printf("cli version: %s", version)
	// Let's do read first
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	t, err := jwt.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(t)
}
