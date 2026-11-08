import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/pages/mailbox_diagnostics_page.dart';

void main() {
  testWidgets('reports good, problem, and unknown without treating unknown as success', (tester) async {
    var checks = 0;
    await tester.pumpWidget(MaterialApp(home: MailboxDiagnosticsPage(
      buildId: 'test', loadDirectory: () async => '{}', loadChecks: () async {
        checks++;
        return [
          (label: 'Screen Recording', state: DiagnosticState.good, detail: 'Granted'),
          (label: 'Accessibility', state: DiagnosticState.problem, detail: 'Denied'),
          (label: 'Local Network', state: DiagnosticState.unknown, detail: 'Check settings'),
        ];
      },
    )));
    await tester.pumpAndSettle();
    expect(find.text('Build: test'), findsOneWidget);
    expect(find.byIcon(Icons.check_circle), findsOneWidget);
    expect(find.byIcon(Icons.cancel), findsOneWidget);
    expect(find.byIcon(Icons.help_outline), findsOneWidget);
    expect(find.textContaining('Needs manual check'), findsOneWidget);
    await tester.tap(find.text('Check again'));
    await tester.pumpAndSettle();
    expect(checks, 2);
  });
}
