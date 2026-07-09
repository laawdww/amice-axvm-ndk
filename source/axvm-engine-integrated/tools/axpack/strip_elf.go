package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

/* stripDebugELF removes .symtab/.strtab via llvm-strip -s (NDK or LLVM_STRIP env). */
func stripDebugELF(path, tool string) error {
	if tool == "" {
		tool = os.Getenv("LLVM_STRIP")
	}
	if tool == "" {
		tool = os.Getenv("STRIP")
	}
	if tool == "" {
		return fmt.Errorf("strip tool not set (use -strip-tool or LLVM_STRIP)")
	}
	if _, err := exec.LookPath(tool); err != nil {
		if _, statErr := os.Stat(tool); statErr != nil {
			return fmt.Errorf("strip tool %q: %w", tool, err)
		}
	}
	tmp := path + ".strip.tmp"
	cmd := exec.Command(tool, "-s", "-o", tmp, path)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	abs, _ := filepath.Abs(path)
	fmt.Fprintf(os.Stderr, "axpack: stripped debug symtab -> %s\n", abs)
	return nil
}
