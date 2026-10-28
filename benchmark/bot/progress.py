"""One editable Telegram activity card, refreshed while blocking work runs."""
import threading
import time

from telegram import TelegramError


class Progress:
    def __init__(self, telegram, chat_id, title, phase='Waiting', interval=8, clock=time.monotonic):
        self.telegram, self.chat_id, self.title = telegram, chat_id, title
        self.phase, self.state, self.interval, self.clock = phase, 'QUEUED', interval, clock
        self.created, self.phase_started = clock(), clock()
        self.frame, self.message_id, self.last_edit = 0, None, 0
        self.lock, self.closed = threading.Lock(), threading.Event()
        self.io_lock = threading.Lock()
        self.worker = None
        self._render(first=True)

    @staticmethod
    def duration(seconds):
        seconds = max(0, int(seconds))
        return '%dm %02ds' % divmod(seconds, 60) if seconds >= 60 else '%ds' % seconds

    def text(self):
        with self.lock:
            state, phase, frame = self.state, self.phase, self.frame
            age, phase_age = self.clock() - self.created, self.clock() - self.phase_started
        if state == 'DONE':
            bar, icon = '■' * 10, '✓'
        elif state in ('FAILED', 'CANCELLED', 'INTERRUPTED', 'PARTIAL'):
            bar, icon = '□' * 10, '!' if state in ('FAILED', 'PARTIAL') else '—'
        else:
            bar = ''.join('■' if (i - frame) % 10 < 3 else '□' for i in range(10))
            icon = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧')[frame % 8]
        return ('%s %s — %s\n[%s] %s\nElapsed: %s | Current task: %s\n'
                'Activity indicator; no completion-time estimate.' %
                (icon, self.title, state, bar, phase[:650], self.duration(age), self.duration(phase_age)))

    def _render(self, first=False, force=False):
        if not first and not force and self.clock() - self.last_edit < 1:
            return
        self.last_edit = self.clock()
        with self.io_lock:
            try:
                if first:
                    receipt = self.telegram.send_message(self.chat_id, self.text())
                    self.message_id = (receipt or {}).get('message_id')
                elif self.message_id is not None:
                    self.telegram.edit_message(self.chat_id, self.message_id, self.text())
            except TelegramError:
                # A deleted card or unavailable Telegram must not stop the benchmark.
                pass

    def start(self, phase=None):
        self.update(phase or self.phase, state='RUNNING')
        if self.worker is None:
            self.worker = threading.Thread(target=self._heartbeat, name='bench-progress', daemon=True)
            self.worker.start()
        return self

    def update(self, phase, state=None):
        if self.closed.is_set():
            return
        with self.lock:
            changed_state = state is not None and state != self.state
            if phase != self.phase:
                self.phase_started = self.clock()
            self.phase = phase
            if state:
                self.state = state
            self.frame += 1
        self._render(force=changed_state)

    def _heartbeat(self):
        while not self.closed.wait(self.interval):
            with self.lock:
                self.frame += 1
            self._render()

    def finish(self, state='DONE', phase='Finished'):
        if self.closed.is_set():
            return
        self.closed.set()
        with self.lock:
            self.state, self.phase = state, phase
        self._render(force=True)
