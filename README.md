Naum OTP PAM
============

This module was provides one-time-password authetication based on HMAC-SHA256 with a shared secret.

It was built as a simple anti-sniffing measure for a challenge on the [Naumachia](https://github.com/nategraf/naumachia) platform, but may be useful to you as an example and/or starting point to writing a PAM module yourself.

Usage
-----

**Build**

Use `make` to build the module and `make install` to put it in your` /lib/security` directory

The module needs to be build as a shared object file, linked with the pam library, and (for HMAC) openssl.

This command does that: `gcc -fPIC -shared src/pam_hmac.c -o bin/pam_hmac.so -lpam -lcrypto`

**Install**

This built shared-object file needs to be placed in `/lib/security` and an entry must be added to the appropriate config in `/etc/pam.d`

The [common-auth](./common-auth) file provides and example of how to enable this module in `/etc/pam.d/common-auth` (such that it is used for all password-based authentication)

Notice that the `pam_naumotp.so` line is place after `pam_permit.so` and `pam_deny.so`. Also notice that `debug`is specified as an aurgument. This is only for testing.

**Test / Experiment**

To test and experitment with the module without locking myself out of my computer I created a `Dockerfile`

With Docker installed, use `docker build -t naumotp-test` to build and `docker run --rm -it naumotp-test bash` to run

In the container shell run `login` (or another pam application). If it works, you will be prompted for your username and password, then the HMAC challenge-response

Use the user "noob" with password "noob" and as configured in the Dockerfile


How I learned to write this module
----------------------------------
I started by looking at [beatgammit's simple-pam repo](https://github.com/beatgammit/simple-pam) and this gave me a starting point.

I leaned more heavily on the work of [Ben Servos](http://ben.akrin.com/?p=1068) as it contained conversation code

This post helped me understand how to use [OpenSSL HMAC](http://www.askyb.com/cpp/openssl-hmac-hasing-example-in-cpp/)

These guides are useful (again origonal found with the help of beatgammit):
* [Writing PAM Modules, Part One](http://linuxdevcenter.com/pub/a/linux/2002/05/02/pam_modules.html)
* [Writing PAM Modules, Part Two](http://linuxdevcenter.com/pub/a/linux/2002/05/23/pam_modules.html)
* [Writing PAM Modules, Part Three](http://linuxdevcenter.com/pub/a/linux/2002/05/30/pam_modules.html)

And of course there is no replacement for reading the docs:
 * [Linux-PAM Module Developer's Guide](http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_MWG.html)
 * [OpenSSL HMAC](https://wiki.openssl.org/index.php/Manual:Hmac(3))
