# QQ database snapshots and authentication failures

A successful page-1 key check does not guarantee that every physical slot in a
QQ database file contains an encrypted database page. NTQQ can reserve file
capacity beyond its committed database size. A newly committed page can also
exist in the WAL before it is written back to its main-file slot.

The reader authenticates page 1, verifies the committed WAL, and builds the
committed database image. It authenticates every WAL frame and each main page
used by that image. An authenticated WAL page takes precedence over the older
main-file slot. File capacity outside the authenticated database extent does
not enter the exported snapshot.

SQLite's header page count is trusted only when it is nonzero and the change
counter equals the version-valid-for field. Otherwise the reader uses the
physical extent and refuses a WAL-only shrink that would discard unverified
pages. A valid final header must agree with the WAL's committed size. See
[SQLite's database size rules](https://sqlite.org/fileformat2.html#in_header_database_size).

Missing or unauthenticated pages inside the committed image still cause failure.
This change does not implement damaged-database recovery or skip arbitrary zero
pages. The existing narrowly checked Windows lock-page exception remains in
place. Only private snapshot files are written by the decoder.

If an export fails, retain the exact error, operating system, client version and
chatlog-keeper version. A later-page authentication failure alone does not prove
that an update changed the encryption key. Do not post keys, chat databases or
message exports in an issue. A successful local export also does not prove that
all server history has been downloaded to the client.
