# Chart archive reproducibility: local tool fidelity

Source remains `193923cc32c52269f66cb8617940b96d9d555b1e` on baseline
`bb92355cf7b6c4a696f44caf52bd5fa1268e7303`; no chart, archive or gate was edited.

The first integrated full preflight passed workflow and the other chart checks,
but the vendored-archive byte comparison failed with host GNU tar 1.34.
`chart-baseline-diagnostic.json` reproduces that exact failure on an isolated
archive of untouched baseline bb92355c. Chart member content and parsed metadata
matched. The only raw tar header changes were `devmajor` / `devminor` and the
resulting checksum: the host wrote octal zero bytes for ordinary files while the
committed archive left those fields empty. Gzip headers matched as well.

The official GNU tar 1.35 source NEWS explicitly documents this format change;
`tar135-release-note.txt` retains the relevant source excerpt. The official source
was downloaded from `https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz`, SHA256
`4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16`.
It was built with `./configure --prefix=/workspace/.phorvex-tools/tar135`,
`make -j2`, and `make install`; configure/build/install logs are retained here.
The local tar executable is version 1.35, SHA256
`7e6952733a113878d95b09a01b93a9bb9702e33f7e4340ba02882aebc1ccd11a`.
No host package or system binary was replaced.

The first setup attempt could not extract xz because the host has no xz executable;
its three setup-failure logs are retained. Extraction then used Python 3.11.17's
standard-library tarfile/lzma implementation with filter=data. Build succeeded.

`tar135-baseline-check.json` runs the unchanged packaging check on a fresh isolated
bb92355c source archive with GNU tar 1.35 first in PATH, exact Helm 3.16.4, and host
gzip 1.12. All eight committed chart archives compare byte-for-byte and exit 0.
This diagnoses an environment format mismatch rather than stale source archives.

The final preflight must rerun every selected job coherently using
`run-final-preflight.sh`. The earlier failure remains a failure; its chart output
must not be replaced or spliced into a passing receipt. Full receipt status is
reported separately in 05-evidence.md.
