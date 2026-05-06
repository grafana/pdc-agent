package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	next := flag.Bool("next", false, "print next version")
	release := flag.Bool("release", false, "release version")
	flag.Parse()

	getLatestCmd := exec.Command("gh", "release", "view", "--json", "tagName", "--jq", ".tagName")
	b, err := getLatestCmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	latestRelease := strings.TrimSpace(string(b))

	nextVer, err := nextPatch(latestRelease)
	if err != nil {
		log.Fatal(err)
	}

	if *next {
		fmt.Println(nextVer)
		os.Exit(0)
	}

	if *release {
		releaseCmd := exec.Command("gh", "release", "create", nextVer, "--generate-notes")
		b, err := releaseCmd.CombinedOutput()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.TrimSpace(string(b)))
		os.Exit(0)
	}
}

func nextPatch(tag string) (string, error) {
	version := strings.TrimPrefix(strings.TrimSpace(tag), "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("expected %q to look like vMAJOR.MINOR.PATCH", tag)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("parse major version: %w", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("parse minor version: %w", err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", fmt.Errorf("parse patch version: %w", err)
	}

	return fmt.Sprintf("v%d.%d.%d", major, minor, patch+1), nil
}
