# Documentation Corrections To Fold In

This note tracks small documentation corrections found during review.

## SECURITY.md Sid Rotation Note

`SECURITY.md` still includes a production-hardening bullet that says to consider
sid rotation on token refresh.

That is stale. Sid rotation on refresh is now implemented and documented in the
README and SPEC. The note should be removed or rewritten as:

> Keep sid rotation on refresh enabled and covered by tests.

This is documentation cleanup only, not a code change.
