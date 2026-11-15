import SwiftUI

@main
struct MacAgentSecurityGuardApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                ContentView()
                    .tabItem {
                        Label("Decision Receipts", systemImage: "lock.shield")
                    }
                PostureReportView()
                    .tabItem {
                        Label("Machine Health", systemImage: "heart.text.square")
                    }
            }
        }
    }
}
