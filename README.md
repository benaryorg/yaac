# yaac – yet another acme-client

Why another one?
Simplicity, mostly.

How is it special?
The purpose of the entire client is to have two subcommands, one to run the validations and the other to get the certificate.
The former command is intended to be run at comparatively short intervals, daily for example, while the latter runs when the certificate is about to expire.
This fixes an issue I've seen in larger deployments; certificate validation either starts failing exactly when you need it, or you start building extensive monitoring for the validations just to see that you forgot that Let's Encrypt requests certificates from an external IP which you have not allowed (please don't use allowlists for ACME anyway, pretty please).
Thus the command to run the validations is as simple as it gets, you run it and check the status code, possibly using `chronic` from *moreutils* in your *crontab*.

# Future?

I will expand this program for my needs which are not very thorough, however I welcome pull requests *and* filed issues alike.
An HTTP challenge, or the likes of it by placing a file onto the file system, is not currently supported but may be in the future.

