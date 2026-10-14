#!/usr/bin/env bash
# Runner 2.337.0 selects bash by .sh extension. Housekeeping cannot fail CI.
if [ -x /usr/local/libexec/phvx-runner-job-completed ]; then
  /usr/local/libexec/phvx-runner-job-completed || true
fi
exit 0
