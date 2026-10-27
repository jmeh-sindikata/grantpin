/// Runs a view model's list load so that a second request never returns
/// before a load has finished.
///
/// A view model starts a load when the daemon becomes reachable
/// (`connectionChanged`), and a caller can ask for another one while it is
/// still in flight. Dropping the second request (the old `guard !isLoading`)
/// let `await refresh()` return with nothing loaded yet. Here the second
/// caller instead waits, and the running load goes once more afterwards, so a
/// request made after a change (a revoke, an add) is never answered with a
/// list that was read before it. Any number of waiting callers share that one
/// extra pass. No timers: a waiter is resumed by the load it joined.
@MainActor
final class LoadCoalescer {
    private(set) var isRunning = false
    private var again = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Runs `body` now, or, when a load is already running, asks it for one
    /// more pass and returns once that pass is done.
    func run(_ body: () async -> Void) async {
        if isRunning {
            again = true
            await withCheckedContinuation { waiters.append($0) }
            return
        }
        isRunning = true
        repeat {
            again = false
            await body()
        } while again
        isRunning = false
        let w = waiters
        waiters = []
        for c in w { c.resume() }
    }
}
