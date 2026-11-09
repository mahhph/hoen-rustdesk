import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

enum DiagnosticState { good, problem, unknown }

typedef Diagnostic = ({String label, DiagnosticState state, String detail});

/// Read-only checks. An unavailable check is unknown, never assumed healthy.
Future<List<Diagnostic>> loadMailboxDiagnostics(
    Future<String> Function() loadDirectory) async {
  final checks = <Diagnostic>[];
  try {
    final value = jsonDecode(await loadDirectory());
    final ok = value is Map && value['service_available'] == true &&
        value['error'] == null && value['identity'] is String &&
        (value['identity'] as String).isNotEmpty && value['machines'] is List;
    checks.add((label: 'Machine directory',
      state: ok ? DiagnosticState.good : DiagnosticState.problem,
      detail: ok ? 'The service returned the registered machine list.' :
        'The service or machine list is unavailable.'));
  } catch (_) {
    checks.add((label: 'Machine directory', state: DiagnosticState.problem,
      detail: 'The service or machine list could not be checked.'));
  }
  if (Platform.isWindows) {
    checks.add((label: 'Incoming connections (firewall)', state: DiagnosticState.unknown,
      detail: 'Check the Remote Desktop inbound rule and active network profile in Windows Defender Firewall.'));
    return checks;
  }
  if (!Platform.isMacOS) return checks;
  try {
    final status = await const MethodChannel('org.rustdesk.rustdesk/host')
        .invokeMapMethod<String, dynamic>('hostPermissionStatus');
    for (final check in [
      (key: 'screenRecording', label: 'Screen Recording', detail: 'Needed to show this Mac’s screen.'),
      (key: 'accessibility', label: 'Accessibility', detail: 'Needed to control this Mac’s mouse and keyboard.'),
    ]) {
      final value = status?[check.key];
      checks.add((label: check.label,
        state: value is! bool ? DiagnosticState.unknown :
            value ? DiagnosticState.good : DiagnosticState.problem,
        detail: check.detail));
    }
  } catch (_) {
    for (final label in ['Screen Recording', 'Accessibility']) {
      checks.add((label: label, state: DiagnosticState.unknown,
        detail: 'Permission status could not be checked.'));
    }
  }
  checks.add(await _firewallStatus());
  checks.add((label: 'Local Network', state: DiagnosticState.unknown,
    detail: 'Check HoenRemoteDev in System Settings → Privacy & Security → Local Network.'));
  return checks;
}

Future<Diagnostic> _firewallStatus() async {
  const label = 'Incoming connections (firewall)';
  try {
    const tool = '/usr/libexec/ApplicationFirewall/socketfilterfw';
    final global = await Process.run(tool, ['--getglobalstate']);
    final globalText = '${global.stdout}'.toLowerCase();
    if (global.exitCode != 0) throw const FormatException();
    if (globalText.contains('state = 0')) {
      return (label: label, state: DiagnosticState.good,
        detail: 'The application firewall is off.');
    }
    if (!globalText.contains('state = 1')) throw const FormatException();
    final blockAll = await Process.run(tool, ['--getblockall']);
    final blockAllText = '${blockAll.stdout}'.toLowerCase();
    if (blockAll.exitCode != 0) throw const FormatException();
    if (blockAllText.contains('set to enabled')) {
      return (label: label, state: DiagnosticState.problem,
        detail: 'The macOS firewall is set to block all incoming connections.');
    }
    if (!blockAllText.contains('set to disabled')) throw const FormatException();
    final appPath = File(Platform.resolvedExecutable).parent.parent.parent.path;
    final app = await Process.run(tool, ['--getappblocked', appPath]);
    final text = '${app.stdout}'.toLowerCase();
    if (app.exitCode != 0) throw const FormatException();
    if (text.contains('is permitted')) {
      return (label: label, state: DiagnosticState.good,
        detail: 'Incoming connections are allowed for this app.');
    }
    if (text.contains('is blocked')) {
      return (label: label, state: DiagnosticState.problem,
        detail: 'Incoming connections are blocked for this app in the macOS firewall.');
    }
  } catch (_) {
    // Leave unrecognized or inaccessible firewall states as unknown.
  }
  return (label: label, state: DiagnosticState.unknown,
    detail: 'Check the app’s incoming connection rule in macOS Firewall settings.');
}

class MailboxDiagnosticsPage extends StatefulWidget {
  const MailboxDiagnosticsPage({super.key, required this.loadDirectory,
    required this.buildId, this.loadChecks});
  final Future<String> Function() loadDirectory;
  final String buildId;
  final Future<List<Diagnostic>> Function()? loadChecks;

  @override
  State<MailboxDiagnosticsPage> createState() => _MailboxDiagnosticsPageState();
}

class _MailboxDiagnosticsPageState extends State<MailboxDiagnosticsPage> {
  late Future<List<Diagnostic>> _checks;
  @override
  void initState() { super.initState(); _refresh(); }
  void _refresh() {
    _checks = widget.loadChecks?.call() ?? loadMailboxDiagnostics(widget.loadDirectory);
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('About & diagnostics')),
    body: Center(child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 640),
      child: FutureBuilder<List<Diagnostic>>(future: _checks, builder: (context, snapshot) {
        return ListView(padding: const EdgeInsets.all(20), children: [
          Text('Remote Desktop', style: Theme.of(context).textTheme.headlineSmall),
          Text('Build: ${widget.buildId}'),
          const SizedBox(height: 16),
          const Text('These checks describe this computer. A green check does not guarantee a remote connection.'),
          if (!snapshot.hasData && !snapshot.hasError)
            const Padding(padding: EdgeInsets.all(20), child: CircularProgressIndicator())
          else if (snapshot.hasError)
            const ListTile(leading: Icon(Icons.help_outline), title: Text('Checks unavailable'))
          else for (final check in snapshot.data!)
            ListTile(
              leading: Icon(check.state == DiagnosticState.good ? Icons.check_circle :
                  check.state == DiagnosticState.problem ? Icons.cancel : Icons.help_outline,
                color: check.state == DiagnosticState.good ? Colors.green :
                  check.state == DiagnosticState.problem ? Colors.red : Colors.orange),
              title: Text(check.label),
              subtitle: Text('${check.state == DiagnosticState.good ? 'OK' : check.state == DiagnosticState.problem ? 'Needs attention' : 'Needs manual check'} — ${check.detail}'),
            ),
          const SizedBox(height: 12),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
            onPressed: () => setState(_refresh), icon: const Icon(Icons.refresh),
            label: const Text('Check again'))),
        ]);
      }))),
  );
}
