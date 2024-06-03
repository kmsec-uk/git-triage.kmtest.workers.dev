# Git Triage
A very specific Cloudflare Worker for a very specific use-case - triaging a
specific threat actor's activity on GitHub.

This actor publishes malware on git repositories, primarily GitHub. This Worker
will retrieve zips within a repo, calculate the sha256 hash of the zip, and
sha256 of the first file within (there's usually only one).

Only GitHub accounts created within 30 days are triaged. Only repositories with
> 50% of root-level contents as zip are triaged.

Please do not use this worker if this criteria does not meet your use-case.