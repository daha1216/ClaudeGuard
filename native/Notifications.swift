// Loaded in ClaudeGuard's own process so macOS attributes permissions and delivery
// to ClaudeGuard, not Script Editor or a command-line helper.
import Foundation
import UserNotifications
import Darwin

struct Input: Decodable { var operation: String; var title: String?; var body: String?; var requestPermission: Bool? }
final class Presenter: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) { completionHandler([.banner, .list, .sound]) }
}
let presenter = Presenter()
func awaitResult<T>(_ seconds: Double, _ operation: (@escaping (T) -> Void) -> Void) -> T? {
    let lock = NSLock(); var result: T?
    operation { value in lock.lock(); result = value; lock.unlock() }
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        lock.lock(); let value = result; lock.unlock()
        if let value = value { return value }
        RunLoop.current.run(until: Date().addingTimeInterval(0.03))
    }
    return nil
}
func permission(_ status: UNAuthorizationStatus) -> String {
    switch status { case .authorized: return "granted"; case .denied: return "denied"; case .provisional: return "provisional"; case .notDetermined: return "not_determined"; default: return "unknown" }
}
func run(_ bytes: Data) throws -> [String: Any] {
    guard Bundle.main.bundleIdentifier == "com.daha.claudeguard" else { return ["ok": false, "error": "not running inside ClaudeGuard.app"] }
    guard bytes.count <= 16384 else { return ["ok": false, "error": "request too large"] }
    let input = try JSONDecoder().decode(Input.self, from: bytes)
    guard ["status", "send"].contains(input.operation) else { return ["ok": false, "error": "unsupported operation"] }
    let center = UNUserNotificationCenter.current(); center.delegate = presenter
    guard var settings: UNNotificationSettings = awaitResult(5, { center.getNotificationSettings(completionHandler: $0) }) else { return ["ok": false, "error": "notification settings timeout"] }
    if input.operation == "status" { return ["ok": true, "permission": permission(settings.authorizationStatus), "alertEnabled": settings.alertSetting == .enabled] }
    if settings.authorizationStatus == .notDetermined && input.requestPermission == true {
        let granted: String? = awaitResult(55) { done in center.requestAuthorization(options: [.alert, .sound]) { value, error in done(value ? "granted" : "denied_" + String((error as NSError?)?.code ?? 0)) } }
        guard granted == "granted" else { return ["ok": false, "permission": granted ?? "pending", "error": "notification permission not granted"] }
        if let refreshed: UNNotificationSettings = awaitResult(5, { center.getNotificationSettings(completionHandler: $0) }) { settings = refreshed }
    }
    guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return ["ok": false, "permission": permission(settings.authorizationStatus), "error": "notification permission required"] }
    let title = input.title ?? "ClaudeGuard"; let body = input.body ?? ""
    guard title.utf8.count <= 1024 && body.utf8.count <= 8192 else { return ["ok": false, "error": "notification text too large"] }
    let content = UNMutableNotificationContent(); content.title = title; content.body = body; content.sound = .default
    let identifier = "claudeguard-" + UUID().uuidString
    let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
    let added: String? = awaitResult(5) { done in center.add(request) { error in done(error == nil ? "ok" : "failed") } }
    guard added == "ok" else { return ["ok": false, "error": "system rejected notification"] }
    var delivered = false
    for _ in 0..<20 {
        let found: Bool? = awaitResult(1) { done in center.getDeliveredNotifications { items in done(items.contains { $0.request.identifier == identifier }) } }
        if found == true { delivered = true; break }
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    }
    return ["ok": true, "permission": permission(settings.authorizationStatus), "accepted": true, "delivered": delivered, "alertEnabled": settings.alertSetting == .enabled]
}
@_cdecl("cg_notification")
public func cgNotification(_ request: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let request = request else { return nil }
    let result: [String: Any]
    do { result = try run(Data(String(cString: request).utf8)) } catch { result = ["ok": false, "error": "invalid notification request"] }
    guard let bytes = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), let json = String(data: bytes, encoding: .utf8) else { return nil }
    return strdup(json)
}
@_cdecl("cg_notification_free")
public func cgNotificationFree(_ result: UnsafeMutablePointer<CChar>?) { free(result) }
