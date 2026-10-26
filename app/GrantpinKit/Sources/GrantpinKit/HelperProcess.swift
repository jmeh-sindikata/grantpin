import Foundation

/// Runs one short-lived helper process (`grantpin init`, `service install`,
/// `import`, or a login shell asked for its PATH) with a replaced
/// environment, a timeout and capped output (docs/UI-SPEC.md 2.6).
///
/// Nothing is inherited: the caller passes the complete environment. Never put
/// a secret value in `arguments` or `environment`; a value that has to reach
/// the helper travels as an open file descriptor on standard input.
enum HelperProcess {
    /// How long a terminated process may linger before SIGKILL.
    static let killGrace: TimeInterval = 2

    /// Starts `executable`, waits for it and returns what it printed. A
    /// non-zero exit is a normal result, not a thrown error. Cancelling the
    /// task, or running past `timeout`, sends SIGTERM and, if the process is
    /// still there `killGrace` seconds later, SIGKILL: an interactive shell
    /// ignores SIGTERM, and the caller must not wait on it forever.
    ///
    /// - Parameter standardInput: the descriptor to use as stdin; nil is
    ///   `/dev/null`. The caller keeps ownership and closes it.
    /// - Throws: `GrantpinError.io` if the process cannot be started.
    static func run(executable: URL, arguments: [String], environment: [String: String],
                    standardInput: FileHandle?, timeout: TimeInterval,
                    outputCap: Int = ImportRunner.outputCap,
                    killGrace: TimeInterval = HelperProcess.killGrace) async throws -> HelperOutput {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        process.standardInput = standardInput ?? FileHandle.nullDevice
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err

        let outBuf = CappedBuffer(cap: outputCap), errBuf = CappedBuffer(cap: outputCap)
        let outReader = PipeReader(out.fileHandleForReading, into: outBuf)
        let errReader = PipeReader(err.fileHandleForReading, into: errBuf)

        let state = RunState(killGrace: killGrace)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<HelperOutput, Error>) in
                process.terminationHandler = { p in
                    state.timer?.cancel()
                    // Let the readers finish what the process wrote. A
                    // grandchild that inherited the pipe (a login shell's rc
                    // file starting a daemon) must not hold us up: give the
                    // readers a moment, then report what has arrived.
                    outReader.wait(upTo: 0.5)
                    errReader.wait(upTo: 0.5)
                    cont.resume(returning: HelperOutput(
                        exitCode: p.terminationStatus,
                        stdout: String(decoding: outBuf.data, as: UTF8.self),
                        stderr: String(decoding: errBuf.data, as: UTF8.self),
                        timedOut: state.timedOut))
                }
                // The timer starts before the process does, so nothing that
                // happens while launching can leave it unwatched.
                let timer = DispatchSource.makeTimerSource(queue: .global())
                timer.schedule(deadline: .now() + timeout)
                timer.setEventHandler { state.timeOut() }
                state.timer = timer
                state.setProcess(process)
                timer.resume()
                do {
                    try process.run()
                } catch {
                    timer.cancel()
                    // The write ends are still ours; closing them ends the readers.
                    try? out.fileHandleForWriting.close()
                    try? err.fileHandleForWriting.close()
                    cont.resume(throwing: GrantpinError.io("cannot start the helper"))
                    return
                }
                state.launched()
            }
        } onCancel: {
            state.cancel()
        }
    }

    /// Reads a pipe to EOF on its own thread into a capped buffer.
    final class PipeReader: @unchecked Sendable {
        private let done = DispatchSemaphore(value: 0)
        init(_ handle: FileHandle, into buffer: CappedBuffer) {
            // Our own descriptor: the Pipe may be released while a reader that
            // was given up on is still waiting for a grandchild to let go.
            let fd = dup(handle.fileDescriptor)
            let semaphore = done
            let thread = Thread {
                var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                while true {
                    let n = read(fd, &bytes, bytes.count)
                    if n > 0 { buffer.append(Data(bytes[0..<n])) } else if n < 0 && errno == EINTR { continue } else { break }
                }
                close(fd)
                semaphore.signal()
            }
            thread.stackSize = 256 * 1024
            thread.start()
        }
        /// Waits for EOF, at most `seconds`.
        func wait(upTo seconds: TimeInterval) {
            _ = done.wait(timeout: .now() + seconds)
        }
    }

    final class CappedBuffer: @unchecked Sendable {
        private let lock = NSLock()
        private let cap: Int
        private var storage = Data()
        init(cap: Int) { self.cap = cap }
        func append(_ d: Data) {
            lock.lock(); defer { lock.unlock() }
            let room = cap - storage.count
            if room > 0 { storage.append(d.prefix(room)) }
        }
        var data: Data { lock.lock(); defer { lock.unlock() }; return storage }
    }

    final class RunState: @unchecked Sendable {
        private let lock = NSLock()
        private let killGrace: TimeInterval
        private var process: Process?
        private var started = false
        private var stopRequested = false
        private(set) var timedOut = false
        var timer: DispatchSourceTimer?

        init(killGrace: TimeInterval) { self.killGrace = killGrace }

        /// Remembers the process before it is run, so the timer can reach it.
        func setProcess(_ p: Process) {
            lock.lock()
            process = p
            lock.unlock()
        }
        /// The process is running now. A stop that was asked for while it was
        /// launching (cancellation, a zero timeout) is carried out here.
        func launched() {
            lock.lock()
            started = true
            let stop = stopRequested
            lock.unlock()
            if stop { stopProcess() }
        }
        func cancel() {
            lock.lock()
            stopRequested = true
            lock.unlock()
            stopProcess()
        }
        func timeOut() {
            lock.lock()
            timedOut = true
            stopRequested = true
            lock.unlock()
            stopProcess()
        }

        /// SIGTERM now; SIGKILL after the grace period if it is still running.
        private func stopProcess() {
            lock.lock()
            let p = started ? process : nil
            lock.unlock()
            guard let p, p.isRunning else { return }
            p.terminate()
            DispatchQueue.global().asyncAfter(deadline: .now() + killGrace) {
                if p.isRunning { kill(p.processIdentifier, SIGKILL) }
            }
        }
    }
}
