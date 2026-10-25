import Foundation

/// Runs one short-lived helper process (`grantd init`, `service install`,
/// `import`, or a login shell asked for its PATH) with a replaced
/// environment, a timeout and capped output (docs/UI-SPEC.md 2.6).
///
/// Nothing is inherited: the caller passes the complete environment. Never put
/// a secret value in `arguments` or `environment`; a value that has to reach
/// the helper travels as an open file descriptor on standard input.
enum HelperProcess {
    /// Starts `executable`, waits for it and returns what it printed. A
    /// non-zero exit is a normal result, not a thrown error. Cancelling the
    /// task, or running past `timeout`, terminates the process.
    ///
    /// - Parameter standardInput: the descriptor to use as stdin; nil is
    ///   `/dev/null`. The caller keeps ownership and closes it.
    /// - Throws: `GrantdError.io` if the process cannot be started.
    static func run(executable: URL, arguments: [String], environment: [String: String],
                    standardInput: FileHandle?, timeout: TimeInterval,
                    outputCap: Int = ImportRunner.outputCap) async throws -> HelperOutput {
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

        let state = RunState()
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
                do {
                    try process.run()
                } catch {
                    // The write ends are still ours; closing them ends the readers.
                    try? out.fileHandleForWriting.close()
                    try? err.fileHandleForWriting.close()
                    cont.resume(throwing: GrantdError.io("cannot start the helper"))
                    return
                }
                state.setProcess(process)
                let timer = DispatchSource.makeTimerSource(queue: .global())
                timer.schedule(deadline: .now() + timeout)
                timer.setEventHandler { state.timeOut() }
                state.timer = timer
                timer.resume()
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
        private var process: Process?
        private var cancelled = false
        private(set) var timedOut = false
        var timer: DispatchSourceTimer?

        func setProcess(_ p: Process) {
            lock.lock()
            process = p
            let stop = cancelled
            lock.unlock()
            if stop, p.isRunning { p.terminate() }
        }
        func cancel() {
            lock.lock()
            cancelled = true
            let p = process
            lock.unlock()
            if let p, p.isRunning { p.terminate() }
        }
        func timeOut() {
            lock.lock()
            timedOut = true
            let p = process
            lock.unlock()
            if let p, p.isRunning { p.terminate() }
        }
    }
}
