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
	// tcRestartMu is nil for ingress-XDP (can't map-collide with TC) and
	// shared between ingress-TC/egress-TC (can collide). See NFConfigs.TCRestartMu.
	go c.pMonitorWorker(progs.IngressXDP, models.XDPIngressType, progs.Ifaces, progs.Mu, nil)
	go c.pMonitorWorker(progs.IngressTC, models.IngressType, progs.Ifaces, progs.Mu, progs.TCRestartMu)
	go c.pMonitorWorker(progs.EgressTC, models.EgressType, progs.Ifaces, progs.Mu, progs.TCRestartMu)
	go c.pMonitorProbeWorker(progs.Probes)
}

// pMonitorWorker scans one direction's chained BPF programs and restarts any
// that aren't running. tcRestartMu (nil for ingress-XDP) is held around each
// restart so ingress-TC/egress-TC never restart a shared-map-path program at once.
func (c *PCheck) pMonitorWorker(bpfProgs map[string]*list.List, direction string, ifaces *map[string]string, mu *sync.RWMutex, tcRestartMu *sync.Mutex) {
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
					// Guards the Stop/Start (or root reload+relink) below, which can
					// unpin/re-pin a map path shared with the other TC direction.
					if tcRestartMu != nil {
						tcRestartMu.Lock()
					}
					if isRoot {
						// Root has no PrevProgMapID, so it can't use LoadBPFProgramChain
						// below. Reload in place via LoadRootProgram and relink only the
						// first child; the rest of the chain is untouched.
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
							// Stop first to clear stale pins, else Start's re-pin at the
							// same path fails because it's still occupied. Log and
							// continue on error so a failed cleanup doesn't block reload.
							if err := bpf.Stop(ifaceName, (*ifaces)[ifaceName], direction, c.Chain); err != nil {
								log.Warn().Err(err).Msgf("pMonitorWorker: BPF Program stop before restart failed for program %s, continuing to reload anyway", bpf.Program.Name)
							}
							if err := bpf.Start(ifaceName, (*ifaces)[ifaceName], direction, c.Chain); err != nil {
								log.Error().Err(err).Msgf("pMonitorWorker: BPF Program start failed for program %s", bpf.Program.Name)
							}
						}
					}
					if tcRestartMu != nil {
						tcRestartMu.Unlock()
					}
				}
				stats.SetWithVersion(0.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, direction, ifaceName, (*ifaces)[ifaceName])
			}
		}
		mu.RUnlock()
	}
}

// reloadRootInPlace reloads a stale root (SeqID 0) program and relinks the
// first child to it, without touching the rest of the chain. root's fields
// are overwritten in place (not swapped as a new *BPF element) so this only
// needs the caller's RLock(), same as every other program's Stop/Start.
// firstChildElem is the element after root, or nil if root is the only program.
func (c *PCheck) reloadRootInPlace(root *BPF, firstChildElem *list.Element, ifaceName, direction string, ifaces *map[string]string) error {
	progType := models.TCType
	if direction == models.XDPIngressType {
		progType = models.XDPType
	}

	// Best-effort cleanup; LoadRootProgram's own stale-pin handling covers any leftovers.
	if err := root.Stop(ifaceName, (*ifaces)[ifaceName], direction, c.Chain); err != nil {
		log.Warn().Err(err).Msgf("pMonitorWorker: root program stop before reload failed for program %s, iface %s, ipv4_address %s, continuing to reload anyway", root.Program.Name, ifaceName, (*ifaces)[ifaceName])
	}

	newRoot, err := LoadRootProgram(ifaceName, direction, progType, root.HostConfig)
	if err != nil {
		return fmt.Errorf("failed to reload root program %s on iface %s direction %s: %w", root.Program.Name, ifaceName, direction, err)
	}

	// Field-by-field copy, not "*root = *newRoot": BPF's atomic fields make go
	// vet reject a whole-struct assignment. RestartCount is kept as-is.
	// Add new fields here if LoadRootProgram starts populating more.
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

	// firstChild isn't restarted, but its Prev* fields must point at the
	// reloaded root so a later independent restart doesn't use a stale map ID.
	firstChild.PrevMapNamePath = root.MapNamePath
	firstChild.PrevProgMapID = root.ProgMapID

	if err := root.PutNextProgFDFromID(int(firstChild.ProgID.Load())); err != nil {
		// Force ProgID back to 0 so the next tick retries the reload+relink
		// instead of treating this half-relinked root as healthy.
		root.ProgID.Store(0)
		return fmt.Errorf("failed to relink program %s to reloaded root on iface %s direction %s: %w", firstChild.Program.Name, ifaceName, direction, err)
	}

	log.Info().Msgf("pMonitor: root BPF program %s on iface %s direction %s reloaded and relinked to %s successfully",
		root.Program.Name, ifaceName, direction, firstChild.Program.Name)
	return nil
}

// pMonitorProbeWorker is pMonitorWorker for probe programs: it scans the flat,
// unchained probe list and restarts any program that isn't running. Probes
// have no interface/direction and no chaining, so no root handling is needed.
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
