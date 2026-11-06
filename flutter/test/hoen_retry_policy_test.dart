import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/common/hoen_retry_policy.dart';

void main() {
  test('Mac mailbox connection errors stay visible instead of trapping the user in retries', () {
    expect(shouldRetryConnectionError(retryRequested: true, isMac: true,
        mailboxMode: true, title: 'Connection Error'), isFalse);
    expect(shouldRetryConnectionError(retryRequested: true, isMac: false,
        mailboxMode: true, title: 'Connection Error'), isTrue);
    expect(shouldRetryConnectionError(retryRequested: true, isMac: true,
        mailboxMode: false, title: 'Connection Error'), isTrue);
    expect(shouldRetryConnectionError(retryRequested: true, isMac: true,
        mailboxMode: true, title: 'Other'), isTrue);
  });
}
