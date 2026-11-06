/// Mailbox connection errors on Mac stay visible until the user dismisses them.
bool shouldRetryConnectionError({
  required bool retryRequested,
  required bool isMac,
  required bool mailboxMode,
  required String title,
}) => retryRequested && !(isMac && mailboxMode && title == 'Connection Error');
