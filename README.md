# Notes
When cloning use: `git clone --recursive` so that submodules get initialized.
(Alternatively you can run `git submodule init` then `git submodule update`
after performing a normal pull.)
See for reference: https://git-scm.com/book/en/v2/Git-Tools-Submodules

# TODO
See github issues. Assign yourself when working on an issue. Open new issues as
appropriate.

# Standards
- Try to use git commit message standards found here
  http://chris.beams.io/posts/git-commit/
- Generally follow linux kernel c coding standards
- Keep line lengths < 81 characters long
- Try to avoid merge bubble commits due to local changes by using `rebase`
- Do not commit binary files (e.g. executables, images, etc.)
- Do not force push
