# Get-TokenFromMemory

This script is intended to use for example purposes only. The goal is to help people understand the importance of securing tokens on devices, which typically means securing the device itself.

## Disclaimer

Don't use this for bad, use it for good.

## How it works

It's a very basic memory scanner.

1. We take a list of known proccesses that might contain access tokens (specified to the script as a PowerShell array with the MonitorProccesses param
2. We look for proccesses that match that condition
3. We loop through that proccesses memory, and do kernel lookups to determine the protection on that memory
4. We build a map of everything that we can read
5. We then loop through that map, fetching the memory, perform UTF8 conversion, then do a match for *access_token*
6. If we find an access_token, we attempt to convert it from its JWT format to show the params of it, and we also dump the token in raw

## What does this mean from a security perspective?

Tokens can typically be replayed - so if you can do this on a machine, for instance, you're in the same context as the user executing some malicious code - you can fetch that users tokens from memory and play them in a different location. Alternatively, if you manage to escalate yourself to administrative permissions - you can even scan the proccesses of other users on the same system.

## How do I secure against this?

1. Don't allow untrusted code to run
2. Follow good security practice, patches, firewalls all that good stuff
3. Deploy unique local administrative passwords to prevent someone from latterally moving across different boxes with something like this
