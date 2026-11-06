import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/pages/mailbox_home_page.dart';

void main() {
  final directory = jsonEncode({
    'service_available': true,
    'identity': 'self',
    'machines': [
      {
        'identity': 'self',
        'display_name': 'This machine',
        'hosting_enabled': true
      },
      {
        'identity': 'off',
        'display_name': 'Disabled machine',
        'hosting_enabled': false
      },
      {'identity': 'host', 'display_name': 'Office', 'hosting_enabled': true},
    ],
  });

  testWidgets('shows eligible other hosts and connects the chosen identity',
      (tester) async {
    String? connected;
    await tester.pumpWidget(MaterialApp(
        home: Scaffold(
            body: MailboxHomePage(
      loadDirectory: () async => directory,
      connect: (id) => connected = id,
    ))));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    expect(find.text('Office'), findsOneWidget);
    expect(find.text('This machine'), findsNothing);
    expect(find.text('Disabled machine'), findsNothing);
    await tester.tap(find.text('Office').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Connect'));
    expect(connected, 'host');
  });

  testWidgets('failed refresh clears the selected host', (tester) async {
    var available = true;
    String? connected;
    await tester.pumpWidget(MaterialApp(
        home: Scaffold(
            body: MailboxHomePage(
      loadDirectory: () async => available
          ? directory
          : '{"service_available":false,"error":"unavailable"}',
      connect: (id) => connected = id,
    ))));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Office').last);
    await tester.pumpAndSettle();
    available = false;
    await tester.tap(find.text('Refresh'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Service or machine list unavailable'),
        findsOneWidget);
    expect(
        tester
            .widget<ElevatedButton>(
                find.widgetWithText(ElevatedButton, 'Connect'))
            .onPressed,
        isNull);
    expect(connected, isNull);
  });

  testWidgets('another machine can be selected after an attempted connection', (tester) async {
    final attempts = <String>[];
    final twoHosts = jsonEncode({
      'service_available': true,
      'identity': 'mac',
      'machines': [
        {'identity': 'lenovo', 'display_name': 'Lenovo', 'hosting_enabled': true},
        {'identity': 'windows', 'display_name': 'Area51', 'hosting_enabled': true},
      ],
    });
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: MailboxHomePage(
      loadDirectory: () async => twoHosts,
      connect: attempts.add,
    ))));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Lenovo').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Connect'));
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Area51').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Connect'));
    expect(attempts, ['lenovo', 'windows']);
  });
}
