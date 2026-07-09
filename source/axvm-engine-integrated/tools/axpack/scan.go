package main

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type scanInsnFail struct {
	Offset int    `json:"offset"`
	Word   string `json:"word"`
	Mnemo  string `json:"mnemo"`
	Hint   string `json:"hint"`
}

type scanSymReport struct {
	Name             string          `json:"name"`
	Addr             string          `json:"addr"`
	Size             int             `json:"size"`
	LiftOK           bool            `json:"lift_ok"`
	AtomicApprox     bool            `json:"atomic_approx,omitempty"`
	AtomicCount      int             `json:"atomic_count,omitempty"`
	AtomicHits       []scanAtomicHit `json:"atomic_hits,omitempty"`
	Priority         int             `json:"priority"`
	InsnWords        int             `json:"insn_words"`
	UnsupportedCount int             `json:"unsupported_count"`
	Unsupported      []scanInsnFail  `json:"unsupported,omitempty"`
	LiftError        string          `json:"lift_error,omitempty"`
}

type scanAtomicHit struct {
	Offset int    `json:"offset"`
	Family string `json:"family"`
}

type scanReport struct {
	Input              string          `json:"input"`
	TotalSymbols       int             `json:"total_symbols"`
	Liftable           int             `json:"liftable"`
	NotLiftable        int             `json:"not_liftable"`
	AtomicApproxCount  int             `json:"atomic_approx_count"`
	CoveragePct        float64         `json:"coverage_pct"`
	UnsupportedByMnemo map[string]int  `json:"unsupported_by_mnemo,omitempty"`
	SuggestedSyms      string          `json:"suggested_syms"`
	Symbols            []scanSymReport `json:"symbols"`
}

func runScan(inPath string, ef *elf.File, raw []byte, targets map[string]bool, reportPath string) error {
	configureCallTargets(buildPLTCallTargetMap(ef))
	funcs, err := collectFuncs(ef, raw, targets)
	if err != nil {
		return err
	}

	rep := scanReport{
		Input:              inPath,
		TotalSymbols:       len(funcs),
		UnsupportedByMnemo: map[string]int{},
		Symbols:            make([]scanSymReport, 0, len(funcs)),
	}

	var liftOKNames []string
	for _, f := range funcs {
		sr := scanSymReport{
			Name: f.Name,
			Addr: fmt.Sprintf("0x%X", f.Addr),
			Size: f.Size,
		}
		if len(f.OrigCode) > 0 {
			sr.InsnWords = len(f.OrigCode) / 4
		}

		atomicHits := diagnoseAtomicApprox(f.OrigCode)
		if len(atomicHits) > 0 {
			sr.AtomicApprox = true
			sr.AtomicCount = len(atomicHits)
			for _, ah := range atomicHits {
				sr.AtomicHits = append(sr.AtomicHits, scanAtomicHit{Offset: ah.Offset, Family: ah.Family})
			}
			rep.UnsupportedByMnemo["ATOMIC_APPROX"] += len(atomicHits)
			rep.AtomicApproxCount++
		}

		fails := diagnoseLift(f.OrigCode, f.Addr)
		if len(fails) > 0 {
			sr.LiftOK = false
			sr.UnsupportedCount = len(fails)
			sr.Priority = scoreSymbolPriority(false, sr.Size, sr.UnsupportedCount, len(fails) > 0)
			for _, u := range fails {
				sr.Unsupported = append(sr.Unsupported, scanInsnFail{
					Offset: u.Offset,
					Word:   fmt.Sprintf("0x%08X", u.Word),
					Mnemo:  u.Mnemo,
					Hint:   u.Hint,
				})
				rep.UnsupportedByMnemo[u.Mnemo]++
			}
			rep.NotLiftable++
		} else {
			_, _, _, err := liftFunc(f.OrigCode, f.Addr)
			if err != nil {
				sr.LiftOK = false
				sr.LiftError = err.Error()
				sr.Priority = scoreSymbolPriority(false, sr.Size, 1, true)
				rep.NotLiftable++
			} else {
				sr.LiftOK = true
				sr.Priority = scoreSymbolPriority(true, sr.Size, 0, false)
				rep.Liftable++
				liftOKNames = append(liftOKNames, f.Name)
			}
		}
		rep.Symbols = append(rep.Symbols, sr)
	}
	sort.Slice(rep.Symbols, func(i, j int) bool {
		if rep.Symbols[i].LiftOK != rep.Symbols[j].LiftOK {
			return !rep.Symbols[i].LiftOK
		}
		if rep.Symbols[i].Priority != rep.Symbols[j].Priority {
			return rep.Symbols[i].Priority > rep.Symbols[j].Priority
		}
		return rep.Symbols[i].Name < rep.Symbols[j].Name
	})

	if rep.TotalSymbols > 0 {
		rep.CoveragePct = float64(rep.Liftable) * 100.0 / float64(rep.TotalSymbols)
	}
	rep.SuggestedSyms = strings.Join(liftOKNames, ",")

	printScanText(rep)

	if reportPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(reportPath, data, 0644); err != nil {
			return err
		}
		fmt.Printf("wrote report %s\n", reportPath)
	}

	if rep.Liftable == 0 && rep.TotalSymbols > 0 {
		return fmt.Errorf("0/%d symbols liftable", rep.TotalSymbols)
	}
	return nil
}

func scoreSymbolPriority(liftOK bool, size int, unsupported int, hasErr bool) int {
	if liftOK {
		return 0
	}
	score := 50
	if hasErr {
		score += 10
	}
	score += unsupported * 8
	if size > 0 {
		score += size / 16
		if score > 100 {
			score = 100
		}
	}
	return score
}

func printScanText(rep scanReport) {
	var b strings.Builder
	fmt.Fprintf(&b, "axpack scan: %s\n", rep.Input)
	fmt.Fprintf(&b, "symbols=%d liftable=%d failed=%d atomic_approx=%d coverage=%.1f%%\n",
		rep.TotalSymbols, rep.Liftable, rep.NotLiftable, rep.AtomicApproxCount, rep.CoveragePct)
	if len(rep.UnsupportedByMnemo) > 0 {
		type kv struct {
			K string
			V int
		}
		arr := make([]kv, 0, len(rep.UnsupportedByMnemo))
		for k, v := range rep.UnsupportedByMnemo {
			arr = append(arr, kv{K: k, V: v})
		}
		sort.Slice(arr, func(i, j int) bool {
			if arr[i].V == arr[j].V {
				return arr[i].K < arr[j].K
			}
			return arr[i].V > arr[j].V
		})
		fmt.Fprintf(&b, "unsupported families:")
		for i, it := range arr {
			if i >= 8 {
				fmt.Fprintf(&b, " ...")
				break
			}
			fmt.Fprintf(&b, " %s=%d", it.K, it.V)
		}
		b.WriteByte('\n')
	}
	for _, s := range rep.Symbols {
		if s.AtomicApprox {
			fmt.Fprintf(os.Stderr, "WARN: %s ATOMIC_APPROX (%d insns) — lift is not thread-safe\n",
				s.Name, s.AtomicCount)
		}
		status := "OK"
		if !s.LiftOK {
			status = "FAIL"
		} else if s.AtomicApprox {
			status = "OK+ATOMIC"
		}
		fmt.Fprintf(&b, "  [%s] %s @%s size=%d insns=%d prio=%d", status, s.Name, s.Addr, s.Size, s.InsnWords, s.Priority)
		if s.AtomicApprox {
			fmt.Fprintf(&b, " atomic_approx=%d", s.AtomicCount)
		}
		if s.UnsupportedCount > 0 {
			fmt.Fprintf(&b, " unsupported=%d", s.UnsupportedCount)
			max := s.UnsupportedCount
			if max > 3 {
				max = 3
			}
			for i := 0; i < max; i++ {
				u := s.Unsupported[i]
				fmt.Fprintf(&b, "\n      +%d %s %s", u.Offset, u.Mnemo, u.Word)
			}
			if s.UnsupportedCount > 3 {
				fmt.Fprintf(&b, "\n      ... +%d more", s.UnsupportedCount-3)
			}
		} else if s.LiftError != "" {
			fmt.Fprintf(&b, " err=%s", s.LiftError)
		}
		b.WriteByte('\n')
	}
	if rep.SuggestedSyms != "" {
		fmt.Fprintf(&b, "\n  suggested -syms: \"%s\"\n", rep.SuggestedSyms)
	} else {
		fmt.Fprintf(&b, "\n  suggested -syms: (none — no lift_ok symbols)\n")
	}
	os.Stdout.WriteString(b.String())
}

func scanFromELF(inPath string, targets map[string]bool, reportPath string) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if ef.Machine != elf.EM_AARCH64 {
		return fmt.Errorf("only ARM64 supported")
	}
	return runScan(inPath, ef, raw, targets, reportPath)
}
