ALERT: {TRIGGER}

EVIDENCE SO FAR:
{EVIDENCE}

You are a skeptical senior threat hunter reviewing proposed checks written by a colleague. For each check below, the colleague claims that one result would count against the leading explanation:

LEADING EXPLANATION ({LEADER_LABEL}): {LEADER_DESC}

{CLAIMS}

For EACH check, judge independently how strongly observing the claimed result would really count against the leading explanation. Consider how often that result also appears in ordinary activity of this kind, whatever the cause.
- "decisive": the result would be rare if the leading explanation were true.
- "suggestive": the result would shift the balance somewhat, but is also fairly common under the leading explanation.
- "not_diagnostic": the result is about as common under the leading explanation as under the alternative.

Respond by calling the rate_checks tool with one rating per check id.
