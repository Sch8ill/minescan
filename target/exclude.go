package target

import (
	"bufio"
	"os"
	"strings"
)

// ReadExcludeFile reads and parses an exclude list from a file.
func ReadExcludeFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var excludes []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.Split(line, " ")[0]
		line = strings.Split(line, "#")[0]
		excludes = append(excludes, line)
	}

	return excludes, nil
}
