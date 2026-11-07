// Local-only comparison probe: prints capture metadata, never saves frame pixels.
import CoreGraphics
import CoreMedia
import Foundation
import ScreenCaptureKit

final class FrameCounter: NSObject, SCStreamOutput, SCStreamDelegate {
    private let lock = NSLock()
    private var total = 0
    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, sampleBuffer.isValid else { return }
        lock.lock(); total += 1; lock.unlock()
    }
    func stream(_ stream: SCStream, didStopWithError error: Error) {
        fputs("stream stopped: \(error)\n", stderr)
    }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return total }
}

@main struct Probe {
    static func main() async {
        guard CGPreflightScreenCaptureAccess() else {
            fputs("Screen Recording permission not granted to probe process\n", stderr); exit(2)
        }
        do {
            let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
            let mainID = CGMainDisplayID()
            var activeCount: UInt32 = 0
            var onlineCount: UInt32 = 0
            let activeResult = CGGetActiveDisplayList(0, nil, &activeCount)
            let onlineResult = CGGetOnlineDisplayList(0, nil, &onlineCount)
            print("main_display=\(mainID) active=\(CGDisplayIsActive(mainID)) online=\(CGDisplayIsOnline(mainID)) active_count=\(activeCount) active_result=\(activeResult.rawValue) online_count=\(onlineCount) online_result=\(onlineResult.rawValue) shareable_displays=\(content.displays.map { $0.displayID })")
            guard let display = content.displays.first(where: { $0.displayID == mainID }) else {
                fputs("primary display not available to ScreenCaptureKit\n", stderr); exit(3)
            }
            print("display=\(display.displayID) dimensions=\(display.width)x\(display.height)")
            let filter = SCContentFilter(display: display, excludingWindows: [])
            let config = SCStreamConfiguration()
            config.width = display.width; config.height = display.height
            config.showsCursor = false
            let counter = FrameCounter()
            let stream = SCStream(filter: filter, configuration: config, delegate: counter)
            try stream.addStreamOutput(counter, type: .screen, sampleHandlerQueue: DispatchQueue(label: "hoen.capture.probe"))
            try await stream.startCapture()
            try await Task.sleep(nanoseconds: 15_000_000_000)
            try await stream.stopCapture()
            let frames = counter.count()
            print("valid_frames=\(frames)")
            exit(frames > 0 ? 0 : 1)
        } catch {
            fputs("capture error: \(error)\n", stderr); exit(4)
        }
    }
}
