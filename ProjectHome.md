The Password Reset is a Bugzilla extension that implements password ageing policy and history

## Installation ##
  1. Download the latest release.
  1. Unpack the download. This will create a directory called "PasswordReset".
  1. Move the "PasswordReset" directory into the "extensions" directory in your Bugzilla installation.
Go to your Bugzilla directory
Apply the patch and run checksetup.pl
```
patch -p0 -i extensions/PasswordReset/patch-4.1.diff
./checksetup.pl
```