package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

func run() error {
	if len(os.Args) != 1 {
		return fmt.Errorf("arguments are forbidden")
	}
	if err := validateEnvironment(os.Getenv); err != nil {
		return err
	}
	if os.Getuid() != runtimeUID || os.Getgid() != runtimeUID {
		return fmt.Errorf("helper requires UID and GID 65532")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return prepare(ctx, newECRClient(), time.Now, outputDirectory)
}

func main() {
	if run() != nil {
		// Never print SDK/OS error strings, response bodies, argv or environment.
		fmt.Fprintln(os.Stderr, "EPSS registry authentication initialization failed")
		os.Exit(1)
	}
}
