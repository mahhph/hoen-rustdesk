import 'dart:convert';

import 'package:flutter/material.dart';

/// Directory data contains registration status, not live availability.
class MailboxHomePage extends StatefulWidget {
  const MailboxHomePage(
      {super.key, required this.loadDirectory, required this.connect});

  final Future<String> Function() loadDirectory;
  final void Function(String identity) connect;

  @override
  State<MailboxHomePage> createState() => _MailboxHomePageState();
}

class _MailboxHomePageState extends State<MailboxHomePage> {
  static const _buildId = String.fromEnvironment('HOEN_BUILD_ID',
      defaultValue: 'development');
  bool _loading = true;
  String? _status;
  String? _identity;
  String? _selected;
  List<({String identity, String name})> _machines = [];

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _status = null;
      _selected = null;
      _machines = [];
      _identity = null;
    });
    try {
      final data = jsonDecode(await widget.loadDirectory());
      if (data is! Map<String, dynamic> || data['service_available'] is! bool) {
        throw const FormatException();
      }
      if (!mounted) return;
      if (data['service_available'] == false) {
        setState(() {
          _loading = false;
          _status =
              'Service or machine list unavailable. Check that Remote Desktop Service is running, then refresh.';
        });
        return;
      }
      if (data['error'] != null) {
        setState(() {
          _loading = false;
          _status = 'Directory unavailable';
        });
        return;
      }
      final identity = data['identity'];
      final machines = data['machines'];
      if (identity is! String || identity.isEmpty || machines is! List) {
        throw const FormatException();
      }
      final results = <({String identity, String name})>[];
      final seen = <String>{};
      for (final machine in machines) {
        if (machine is! Map<String, dynamic> ||
            machine['identity'] is! String ||
            machine['display_name'] is! String ||
            machine['hosting_enabled'] is! bool) {
          throw const FormatException();
        }
        final id = machine['identity'] as String;
        final name = machine['display_name'] as String;
        if (id.isEmpty || name.isEmpty || !seen.add(id)) {
          throw const FormatException();
        }
        if (id != identity && machine['hosting_enabled'] == true) {
          results.add((identity: id, name: name));
        }
      }
      if (!mounted) return;
      setState(() {
        _loading = false;
        _identity = identity;
        _machines = results;
      });
    } catch (_) {
      if (mounted) {
        setState(() {
          _loading = false;
          _status = 'Directory unavailable';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 440),
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Remote Desktop Client',
                style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 4),
            Text('Build: $_buildId', style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 8),
            const Text('Choose a computer to connect to.'),
            if (_identity != null) ...[
              const SizedBox(height: 4),
              Text('Remote Desktop Service connected',
                  style: Theme.of(context).textTheme.bodySmall),
            ],
            const SizedBox(height: 16),
            if (_loading)
              const Text('Loading registered machines…')
            else if (_status != null)
              Text(_status!)
            else if (_machines.isEmpty)
              const Text('No other registered machines have hosting enabled.')
            else
              DropdownButtonFormField<String>(
                value: _selected,
                decoration: const InputDecoration(
                    labelText: 'Registered machine',
                    isDense: true,
                    border: OutlineInputBorder()),
                isExpanded: true,
                items: _machines
                    .map((machine) => DropdownMenuItem(
                          value: machine.identity,
                          child: Text(machine.name,
                              overflow: TextOverflow.ellipsis),
                        ))
                    .toList(),
                onChanged: (value) => setState(() => _selected = value),
              ),
            const SizedBox(height: 12),
            Wrap(spacing: 12, children: [
              ElevatedButton(
                  onPressed: _loading || _selected == null
                      ? null
                      : () => widget.connect(_selected!),
                  child: const Text('Connect')),
              OutlinedButton(
                  onPressed: _loading ? null : _refresh,
                  child: const Text('Refresh')),
            ]),
            const SizedBox(height: 10),
            Text('Registered does not mean online.',
                style: Theme.of(context).textTheme.bodySmall),
          ]),
        ),
      ),
    );
  }
}
