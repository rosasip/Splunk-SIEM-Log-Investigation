# SIEM Log Analysis with Splunk

## Overview

This project involved standing up a Splunk environment and using SPL (Search Processing Language) to investigate structured log data, simulating the kind of search, filter, and aggregation work a SOC analyst performs during a real investigation. Rather than following a guided walkthrough, this was a capture-the-flag style exercise: I was given raw indexed data and had to form my own hypotheses and queries to answer investigative questions, without being told which fields or search patterns to use ahead of time.

## Environment

- Splunk Enterprise (Docker container)
- Two indexed datasets: a media metadata dataset (Netflix titles) and a multi-source security log set (proxy logs, failed logins, uploaded file hashes, web server logs)
- All queries written and run through Splunk's Search & Reporting interface

## Skills Practiced

- Building SPL searches using field filters, wildcards, and boolean logic
- Using `stats`, `sort`, and `rex` to aggregate and extract data from semi-structured fields
- Verifying field names and data structure before querying, rather than assuming a schema
- Correlating events across multiple log sources by timestamp and shared identifiers (IP address, filename, hash)
- Documenting search logic alongside findings for reproducibility

## Investigation: Structured Data Search

I explored a large indexed dataset of media titles to practice core search and aggregation patterns. Sample findings:

**How many TV shows are in the Docuseries genre?**
```
index=main host=Netflix type="TV Show" listed_in="*Docuseries*" | stats count
```
Result: 395

<img width="1440" height="875" alt="Screenshot 2026-07-07 at 7 26 39 PM" src="https://github.com/user-attachments/assets/5619e1ce-c6aa-4202-96a2-b6db6aa86633" />

<br>
<br>

## Which release year had the most titles rated G?
```
index=main host=Netflix type="Movie" rating="G" | stats count by release_year | sort -count | head 5
```
Result: 2009 (4 titles)

**Finding the longest-running series by extracting a number from a text field:**
```
index=main host=Netflix type="TV Show" | rex field=duration "(?<num_seasons>\d+)" | eval num_seasons=tonumber(num_seasons) | sort -num_seasons | table title, duration, rating | head 5
```
This one required extracting a numeric value out of a text field (e.g., "17 Seasons") using `rex` before it could be sorted numerically, since Splunk treats the raw field as a string.

<img width="1440" height="875" alt="Screenshot 2026-07-07 at 7 27 23 PM" src="https://github.com/user-attachments/assets/146ceadc-f9d2-4006-8dbd-8b803b2259ec" />

<br>

## Investigation: Correlating a File Upload Across Log Sources

The second half of this project simulated tracing a malicious file upload across multiple, independently-formatted log sources; a common real-world SOC task where no single log tells the whole story.

Starting point: a known malicious file hash.

```
index=pathcode host=uploadedhashes 3AADBF7E527FC1A050E1C97FEA1CBA4D
```

This identified the source IP address, user agent string, and filename tied to the upload.

<img width="1440" height="875" alt="Screenshot 2026-07-07 at 7 27 49 PM" src="https://github.com/user-attachments/assets/7770c04a-dd83-4531-8f3c-e780aaf5e3b4" />

<br>

From there, I cross-referenced that IP against the web server and failed login logs to build out the fuller picture of what led up to the upload, including checking for timestamp alignment between datasets before assuming two events were related. One early hypothesis (that a set of login attempts from the same IP a few hours earlier were tied to the upload) didn't hold up once I compared timestamps closely, which reinforced how easy it is to draw the wrong conclusion in log analysis without verifying time correlation first.

## Reflection

**What field do you think is most important for logs to have?**

Timestamp. While correlating the file upload with earlier activity from the same IP address, I found that the events I initially assumed were connected actually occurred almost three hours apart. Without accurate, consistently formatted timestamps across log sources, it's easy to build the wrong narrative around an incident. A SIEM's core value is being able to line up events from different systems by time, so that correlation breaks down without it.

## Key Takeaways

- The same SPL patterns (filtering by field, aggregating with `stats`, chaining searches with pipes) apply whether you're querying media metadata or security logs; the underlying skill is interpreting structured data, not memorizing one dataset.
- CTF-style investigations without a guided answer path better mirror real SOC work, where you're given data but not told what to look for.
- Cross-referencing multiple log sources by a shared identifier (IP, hash, filename) is central to incident investigation, but requires careful attention to timestamps to avoid false correlation.
