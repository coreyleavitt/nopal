## State transition -> action mapping.
##
## Determines what actions the daemon should take when an interface
## transitions between states.

import ./tracker

type
  TransitionAction* = enum
    taRegenerateNftables
    taAddRoutes
    taRemoveRoutes
    taUpdateDns
    taRemoveDns
    taBroadcastEvent
    taWriteStatus

  TransitionResult* = object
    actions*: seq[TransitionAction]
    index*: int
    newState*: InterfaceState

proc actionsForTransition*(name: string, index: int, mark: uint32,
                           oldState, newState: InterfaceState): TransitionResult =
  ## Determine what actions to take for a state transition.
  var actions: seq[TransitionAction]

  case oldState
  of isDegraded:
    case newState
    of isOnline:
      # Degraded -> Online: routes and DNS already present, no changes
      discard
    of isOffline:
      # Degraded -> Offline: remove from routing
      actions.add(taRemoveRoutes)
      actions.add(taRegenerateNftables)
      actions.add(taRemoveDns)
    else: discard
  of isOnline:
    case newState
    of isDegraded:
      # Online -> Degraded: stays in policy, no route changes
      discard
    of isOffline:
      # Online -> Offline: remove from routing
      actions.add(taRemoveRoutes)
      actions.add(taRegenerateNftables)
      actions.add(taRemoveDns)
    else: discard
  of isProbing:
    case newState
    of isOnline:
      # Probing -> Online: add to routing
      actions.add(taAddRoutes)
      actions.add(taRegenerateNftables)
      actions.add(taUpdateDns)
    of isDegraded:
      # Probing -> Degraded: reachable but poor quality, add to routing
      actions.add(taAddRoutes)
      actions.add(taRegenerateNftables)
      actions.add(taUpdateDns)
    of isOffline:
      # Probing -> Offline: no routing changes
      discard
    else: discard
  of isOffline, isInit:
    case newState
    of isProbing:
      # Offline/Init -> Probing: no routing changes, probes determine next state
      discard
    of isOnline:
      # Direct to Online (e.g. initial_state=online)
      actions.add(taAddRoutes)
      actions.add(taRegenerateNftables)
      actions.add(taUpdateDns)
    else: discard

  # Always broadcast state changes and write status file
  actions.add(taBroadcastEvent)
  actions.add(taWriteStatus)

  TransitionResult(actions: actions, index: index, newState: newState)

when isMainModule:
  import std/unittest

  suite "state transitions":
    test "online transition adds routes and nftables":
      let r = actionsForTransition("wan", 0, 0x0100, isProbing, isOnline)
      check taAddRoutes in r.actions
      check taRegenerateNftables in r.actions
      check taUpdateDns in r.actions

    test "offline transition removes routes and dns":
      let r = actionsForTransition("wan", 0, 0x0100, isDegraded, isOffline)
      check taRemoveRoutes in r.actions
      check taRegenerateNftables in r.actions
      check taRemoveDns in r.actions

    test "degraded to online has no route changes":
      let r = actionsForTransition("wan", 0, 0x0100, isDegraded, isOnline)
      check taAddRoutes notin r.actions
      check taRegenerateNftables notin r.actions
      check taWriteStatus in r.actions

    test "probing to degraded adds routes":
      let r = actionsForTransition("wan", 0, 0x0100, isProbing, isDegraded)
      check taAddRoutes in r.actions
      check taRegenerateNftables in r.actions
      check taUpdateDns in r.actions

    test "all transitions write status file":
      let transitions = [
        (isInit, isProbing),
        (isProbing, isOnline),
        (isProbing, isDegraded),
        (isOnline, isDegraded),
        (isDegraded, isOffline),
        (isDegraded, isOnline),
      ]
      for (old, newSt) in transitions:
        let r = actionsForTransition("wan", 0, 0x0100, old, newSt)
        check taWriteStatus in r.actions
