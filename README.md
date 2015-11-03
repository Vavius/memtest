# memtest
Utility for testing RAM on your mac system. Supports OS X 10.7 and above. This is a contents of dmg image obtained from http://www.memtestosx.org

Site above requires a small fee to be paid in order to download, but this software is licensed under GPLv2 and provided here for free.

## Usage
Just run `./memtest`

In order to test as much memory as possible, it is advised to run memtest in single user mode:

1. To boot into single user mode, reboot you mac and hold `command-S`
2. Mount filesystem `/sbin/mount -uw /`
3. Go to directory where you cloned the repo `cd /Users/user/this_repo_path/memtest`
4. Run memtest `./memtest all 3 -l` - this command will run test 3 times, using all available memory and saving output to log file
