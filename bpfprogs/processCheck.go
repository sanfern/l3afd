// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package bpfprogs provides primitives for BPF process monitoring.
package bpfprogs

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/stats"
	"github.com/rs/zerolog/log"
)

type PCheck struct {
	MaxRetryCount     int
	Chain             bool
	RetryMonitorDelay time.Duration
}

func NewPCheck(rc int, chain bool, interval time.Duration) *PCheck {
	c := &PCheck{
		MaxRetryCount:     rc,
		Chain:             chain,
		RetryMonitorDelay: interval,
	}
	return c
}

func (c *PCheck) PCheckStart(progs *BpfProgSet) {
	go c.pMonitorWorker(progs.IngressXDP, models.XDPIngressType, progs.Ifaces, progs.Mu)
	go c.pMonitorWorker(progs.IngressTC, models.IngressType, progs.Ifaces, progs.Mu)
	go c.pMonitorWorker(progs.EgressTC, models.EgressType, progs.Ifaces, progs.Mu)
	go c.pMonitorProbeWorker(progs.Probes)
}

func (c *PCheck) pMonitorWorker(bpfProgs map[string]*list.List, direction string, ifaces *map[string]string, mu *sync.RWMutex) {
	for range time.NewTicker(c.RetryMonitorDelay).C {
		if models.IsReadOnly {
			log.Info().Msgf("Not monitoring because we are in readonly state")
			return
		}
		mu.RLock()
		for ifaceName, bpfList := range bpfProgs {
			if bpfList == nil { // no bpf programs are running
				continue
			}
			for e := bpfList.Front(); e != nil; e = e.Next() {
				bpf := e.Value.(*BPF)
				isRoot := c.Chain && bpf.Program.SeqID == 0
				if bpf.Program.AdminStatus == models.Disabled {
					continue
				}
				if bpf.Deploying.Load() {
					log.Debug().Msgf("pMonitor: skipping %s on %s, initial deployment in flight", bpf.Program.Name, ifaceName)
					continue
				}
				userProgram, bpfProgram, _ := bpf.isRunning()
				if userProgram && bpfProgram {
					stats.SetWithVersion(1.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, direction, ifaceName, (*ifaces)[ifaceName])
					continue
				}
				// Not running trying to restart
				if bpf.RestartCount < c.MaxRetryCount && bpf.Program.AdminStatus == models.Enabled {
					bpf.RestartCount++
					log.Warn().Msgf("pMonitor BPF Program is not running. Restart attempt: %d, program name: %s, iface: %s",
						bpf.RestartCount, bpf.Program.Name, ifaceName)
					if isRoot {
						// Root can't go through the generic Stop/Start path
						// below: LoadBPFProgramChain requires a non-zero
						// PrevProgMapID, which root intentionally has none of
						// (it has no predecessor). Reload it via
						// LoadRootProgram instead, in place, and relink only
						// the first surviving child - the rest of the chain
						// is untouched. Mutating bpf's fields in place (vs.
						// swapping the list element) keeps this inside the
						// same RLock() every other program here already
						// relies on for its own Stop/Start.
						if err := c.reloadRootInPlace(bpf, e.Next(), ifaceName, direction, ifaces); err != nil {
							log.Error().Err(err).Msgf("pMonitorWorker: root program reload/relink failed for program %s", bpf.Program.Name)
						}
					} else {
						//  User program is a daemon and not running, but the BPF program is loaded
						if !userProgram && bpfProgram {
							if err := bpf.StartUserProgram(ifaceName, direction, c.Chain); err != nil {
								log.Error().Err(err).Msgf("pMonitorWorker: BPF Program start user program failed for program %s", bpf.Program.Name)
							}
						}
						// BPF program is not loaded.
						if !bpfProgram {
							log.Warn().Msgf("%s BPF program is not loaded, %s program reloading ...", bpf.Program.EntryFunctionName, bpf.Program.Name)
							// Stop first to clean up any stale pins left behind by the
							// previous (now unloaded/detached) instance - Start's
							// re-pin of the program/link/maps at the same
							// deterministic path (see ProgPinPath/LinkPinPath)
							// otherwise fails because that path is still occupied.
							// This must run regardless of UserProgramDaemon: Stop's
							// own daemon-process kill is separately gated on
							// UserProgramDaemon/userProgram internally, but its BPF
							// unload/unpin step is not, and is exactly what a plain
							// (non-daemon) XDP/TC program needs here too. Drift is
							// precisely the scenario where Stop can itself error
							// (link/pins already gone) - log and continue to Start
							// rather than abort, so a failing cleanup doesn't block
							// the reload it is meant to enable.
							if err := bpf.Stop(ifaceName, (*ifaces)[ifaceName], direction, c.Chain); err != nil {
								log.Warn().Err(err).Msgf("pMonitorWorker: BPF Program stop before restart failed for program %s, continuing to reload anyway", bpf.Program.Name)
							}
							if err := bpf.Start(ifaceName, (*ifaces)[ifaceName], direction, c.Chain); err != nil {
								log.Error().Err(err).Msgf("pMonitorWorker: BPF Program start failed for program %s", bpf.Program.Name)
							}
						}
					}
				}
				stats.SetWithVersion(0.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, direction, ifaceName, (*ifaces)[ifaceName])
			}
		}
		mu.RUnlock()
	}
}

// reloadRootInPlace reloads a stale root (SeqID 0) program and relinks the
// first surviving child to it, without stopping/restarting that child or
// anything after it in the chain. Only the root<->first-child link was ever
// broken by root going stale; every other child<->child link in the list was
// never touched and is still valid, so a full chain Stop+Start cascade is
// unnecessary and would needlessly interrupt otherwise-healthy programs on
// this interface/direction.
//
// root's fields are overwritten in place rather than swapping in a new *BPF
// list element, so (like every other program's Stop/Start call above) this
// only needs the caller's RLock() - no separate write-lock pass. The caller
// has already incremented root.RestartCount; that increment, and root's
// object identity, are deliberately preserved here.
//
// firstChildElem is the list element immediately after root, or nil if root
// is the only program in the chain.
func (c *PCheck) reloadRootInPlace(root *BPF, firstChildElem *list.Element, ifaceName, direction string, ifaces *map[string]string) error {
	progType := models.TCType
	if direction == models.XDPIngressType {
		progType = models.XDPType
	}

	// Best-effort cleanup of the stale root's kernel/pin state before loading
	// a replacement at the same pin paths. A failure here is logged, not
	// fatal: LoadRootProgram's own CleanStalePins/RemoveRootProgMapFile
	// handle leftover pins the same way they handle an unclean l3afd crash.
	if err := root.Stop(ifaceName, (*ifaces)[ifaceName], direction, c.Chain); err != nil {
		log.Warn().Err(err).Msgf("pMonitorWorker: root program stop before reload failed for program %s, continuing to reload anyway", root.Program.Name)
	}

	newRoot, err := LoadRootProgram(ifaceName, direction, progType, root.HostConfig)
	if err != nil {
		return fmt.Errorf("failed to reload root program on iface %s direction %s: %w", ifaceName, direction, err)
	}

	// Copy newRoot's loaded state field-by-field into the existing root
	// object instead of "*root = *newRoot": BPF carries atomic.Uint32/
	// atomic.Bool fields, which go vet's copylocks check rejects as a whole-
	// struct assignment. RestartCount is deliberately NOT copied - the
	// caller's increment above must survive. If BPF gains new fields that
	// LoadRootProgram populates, add them here too.
	root.Program = newRoot.Program
	root.Cmd = newRoot.Cmd
	root.FilePath = newRoot.FilePath
	root.PrevMapNamePath = newRoot.PrevMapNamePath
	root.MapNamePath = newRoot.MapNamePath
	root.BpfMaps = newRoot.BpfMaps
	root.MetricsBpfMaps = newRoot.MetricsBpfMaps
	root.ProgMapCollection = newRoot.ProgMapCollection
	root.ProgMapID = newRoot.ProgMapID
	root.PrevProgMapID = newRoot.PrevProgMapID
	root.Link = newRoot.Link
	root.ProbeLinks = newRoot.ProbeLinks
	root.IfaceName = newRoot.IfaceName
	root.ProgID.Store(newRoot.ProgID.Load())

	if firstChildElem == nil {
		// Root is the only program in the chain; nothing left to relink.
		return nil
	}
	firstChild := firstChildElem.Value.(*BPF)

	// Bookkeeping only: firstChild itself is not restarted, but its
	// PrevMapNamePath/PrevProgMapID must still be updated to point at the
	// reloaded root. If firstChild is ever independently restarted later for
	// an unrelated reason, its own LoadBPFProgramChain does
	// ebpf.NewMapFromID(b.PrevProgMapID) and hard fails if that ID is stale -
	// this keeps it pointed at a live map.
	firstChild.PrevMapNamePath = root.MapNamePath
	firstChild.PrevProgMapID = root.ProgMapID

	if err := root.PutNextProgFDFromID(int(firstChild.ProgID.Load())); err != nil {
		// root is otherwise healthy now, so leaving its ProgID as-is would
		// make the next tick's isRunning() check report "fine" forever,
		// stranding the chain with no automatic retry. Force it back to
		// stale so the next tick retries the reload+relink (bounded by
		// RestartCount, already incremented by the caller).
		root.ProgID.Store(0)
		return fmt.Errorf("failed to relink program %s to reloaded root on iface %s direction %s: %w", firstChild.Program.Name, ifaceName, direction, err)
	}

	log.Info().Msgf("pMonitor: root BPF program %s on iface %s direction %s reloaded and relinked to %s successfully",
		root.Program.Name, ifaceName, direction, firstChild.Program.Name)
	return nil
}

func (c *PCheck) pMonitorProbeWorker(bpfProgs *list.List) {
	for range time.NewTicker(c.RetryMonitorDelay).C {
		if bpfProgs == nil {
			time.Sleep(time.Second)
			continue
		}
		for e := bpfProgs.Front(); e != nil; e = e.Next() {
			bpf := e.Value.(*BPF)
			if bpf.Program.AdminStatus == models.Disabled {
				continue
			}
			if bpf.Deploying.Load() {
				log.Debug().Msgf("pMonitorProbeWorker: skipping %s, initial deployment in flight", bpf.Program.Name)
				continue
			}
			userProgram, bpfProgram, _ := bpf.isRunning()
			if userProgram && bpfProgram {
				stats.SetWithVersion(1.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, "", "", "")
				continue
			}

			// Not running trying to restart
			if bpf.RestartCount < c.MaxRetryCount && bpf.Program.AdminStatus == models.Enabled {
				bpf.RestartCount++
				log.Warn().Msgf("pMonitorProbeWorker: BPF Program is not running. Restart attempt: %d, program name: %s, iface: %s",
					bpf.RestartCount, bpf.Program.Name, "")
				//  User program is a daemon and not running, but the BPF program is loaded
				if !userProgram && bpfProgram {
					if err := bpf.StartUserProgram("", "", c.Chain); err != nil {
						log.Error().Err(err).Msgf("pMonitorProbeWorker: BPF Program start user program failed for program %s", bpf.Program.Name)
					}
				}
				// BPF program is not loaded.
				// if user program is daemon then stop it and restart both the programs
				if !bpfProgram {
					log.Warn().Msgf("%s BPF program is not loaded, %s program reloading ...", bpf.Program.EntryFunctionName, bpf.Program.Name)
					// User program is a daemon and running, stop before reloading the BPF program
					if bpf.Program.UserProgramDaemon && userProgram {
						if err := bpf.Stop("", "", "", c.Chain); err != nil {
							log.Error().Err(err).Msgf("pMonitorProbeWorker: BPF Program stop failed for program %s", bpf.Program.Name)
						}
					}
					if err := bpf.Start("", "", "", c.Chain); err != nil {
						log.Error().Err(err).Msgf("pMonitorProbeWorker: BPF Program start failed for program %s", bpf.Program.Name)
					}
				}
			} else {
				stats.SetWithVersion(0.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, "", "", "")
			}
		}
	}
}
